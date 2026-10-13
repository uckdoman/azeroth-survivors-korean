import hashlib
import json
import pathlib
import re
import struct

import mpyq


ASSIGNMENT = re.compile(rb'''(?m)^([A-Z_][A-Z0-9_]*)[ \t]*=[ \t]*("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*')''')
BASE_ORDER = ('dbc.mpq', 'speech.mpq', 'fonts.mpq', 'interface.mpq', 'misc.mpq', 'sound.mpq', 'wmo.mpq', 'terrain.mpq', 'texture.mpq', 'model.mpq')
API_KEY_TABLES = ('DBFilesClient\\SpellDispelType.dbc',)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class RawMPQ(mpyq.MPQArchive):
    def read_file(self, filename, force_decompress=False):
        entry = self.get_hash_table_entry(filename)
        if entry is None:
            return None
        block = self.block_table[entry.block_table_index]
        if block.flags & 0x02000000:
            return None
        if block.flags == 0x80000000:
            self.file.seek(self.header['offset'] + block.offset)
            raw = self.file.read(block.archived_size)
            if len(raw) != block.size or block.archived_size != block.size:
                raise ValueError('Invalid raw MPQ member size')
            return raw
        return super().read_file(filename, force_decompress)


def _mount(data_dir):
    names = {p.name.lower(): p for p in sorted(pathlib.Path(data_dir).iterdir()) if p.is_file()}
    paths = [names[n] for n in BASE_ORDER if n in names]
    if 'patch.mpq' in names:
        paths.append(names['patch.mpq'])
    # Match the game's one-character patch glob and ascending priority.
    paths.extend(names[n] for n in sorted(names) if re.fullmatch(r'patch-.\.mpq', n) and n != 'patch-z.mpq')
    if 'speech2.mpq' in names:
        paths.append(names['speech2.mpq'])
    if not paths:
        raise ValueError('No source MPQ archives found')
    archives = []
    try:
        for path in paths:
            archives.append(RawMPQ(str(path), listfile=False))
    except Exception:
        for archive in archives:
            archive.file.close()
        raise
    return archives, [p.name for p in paths]


def _effective(archives, name):
    for archive in reversed(archives):
        if archive.get_hash_table_entry(name) is not None:
            return archive.read_file(name)
    return None


def _dbc(raw, meta):
    if len(raw) < 20:
        return None, 0, 'invalid-header'
    magic, rows, fields, width, pool_size = struct.unpack_from('<4s4I', raw)
    pool_start = 20 + rows * width
    if magic != b'WDBC' or fields != meta['field_count'] or width != meta['record_width'] or width != fields * 4:
        return None, 0, 'changed-schema'
    if pool_start + pool_size != len(raw):
        return None, 0, 'invalid-size'
    pool = raw[pool_start:]
    modified = bytearray(raw[:pool_start])
    new_pool = bytearray(pool)
    added = {}
    matched = 0
    for column, values in meta['string_columns'].items():
        column = int(column)
        if not 0 <= column < fields:
            raise ValueError('Invalid dictionary string column')
        for index in range(rows):
            pos = 20 + index * width + column * 4
            offset = struct.unpack_from('<I', raw, pos)[0]
            if offset == 0:
                continue
            if offset >= pool_size:
                return None, 0, 'invalid-string-offset'
            end = pool.find(b'\0', offset)
            if end < 0:
                return None, 0, 'unterminated-string'
            try:
                english = pool[offset:end].decode('utf-8')
            except UnicodeDecodeError:
                return None, 0, 'unsupported-string-encoding'
            korean = values.get(english)
            if korean is None:
                continue
            if korean not in added:
                added[korean] = len(new_pool)
                new_pool.extend(korean.encode('utf-8') + b'\0')
            struct.pack_into('<I', modified, pos, added[korean])
            matched += 1
    if not matched:
        return None, 0, 'no-known-strings'
    struct.pack_into('<I', modified, 16, len(new_pool))
    modified.extend(new_pool)
    return bytes(modified), matched, None


def _globals(raw, assignments):
    matched = 0

    def replace(match):
        nonlocal matched
        item = assignments.get(match.group(1).decode('ascii'))
        if item is None or match.group(2) != item['english_literal'].encode('utf-8'):
            return match.group(0)
        matched += 1
        relative = match.start(2) - match.start()
        return match.group(0)[:relative] + item['korean_literal'].encode('utf-8')

    result = ASSIGNMENT.sub(replace, raw)
    return (result if matched else None), matched


def _write_exclusive(output, raw):
    created = False
    complete = False
    try:
        with pathlib.Path(output).open('xb') as file:
            created = True
            file.write(raw)
        complete = True
    finally:
        if created and not complete:
            pathlib.Path(output).unlink(missing_ok=True)


def _write_mpq(files, output):
    mpq = mpyq.MPQArchive.__new__(mpyq.MPQArchive)
    files = dict(files)
    files['(listfile)'] = '\r\n'.join(files).encode('utf-8')
    slots = 1
    while slots < len(files) * 2:
        slots *= 2
    hashes = [(0xffffffff, 0xffffffff, 0xffff, 0xffff, 0xffffffff)] * slots
    blocks = []
    body = bytearray(b'\0' * 32)
    for index, (name, raw) in enumerate(files.items()):
        offset = len(body)
        body.extend(raw)
        blocks.append((offset, len(raw), len(raw), 0x80000000))
        slot = mpq._hash(name, 'TABLE_OFFSET') & (slots - 1)
        while hashes[slot][4] != 0xffffffff:
            slot = (slot + 1) & (slots - 1)
        hashes[slot] = (mpq._hash(name, 'HASH_A'), mpq._hash(name, 'HASH_B'), 0, 0, index)

    def encrypt(data, key):
        seed = 0xEEEEEEEE
        result = bytearray()
        for (plain,) in struct.iter_unpack('<I', data):
            seed = (seed + mpq.encryption_table[0x400 + (key & 0xff)]) & 0xffffffff
            result.extend(struct.pack('<I', plain ^ ((key + seed) & 0xffffffff)))
            key = (((~key << 21) + 0x11111111) | (key >> 11)) & 0xffffffff
            seed = (plain + seed + (seed << 5) + 3) & 0xffffffff
        return result

    hash_offset = len(body)
    body.extend(encrypt(b''.join(struct.pack('<IIHHI', *h) for h in hashes), mpq._hash('(hash table)', 'TABLE')))
    block_offset = len(body)
    body.extend(encrypt(b''.join(struct.pack('<IIII', *b) for b in blocks), mpq._hash('(block table)', 'TABLE')))
    body[:32] = struct.pack('<4sIIHHIIII', b'MPQ\x1a', 32, len(body), 0, 3, hash_offset, block_offset, slots, len(blocks))
    _write_exclusive(output, body)
    return digest(body)


def apply(data_dir, templatePath, assetDbPath, outputPath):
    database = json.loads(pathlib.Path(assetDbPath).read_text(encoding='utf-8'))
    template_bytes = pathlib.Path(templatePath).read_bytes()
    if database.get('schema') != 1 or digest(template_bytes) != database['template_sha256']:
        raise ValueError('Asset template does not match the dictionary')
    dictionary_names = {name.casefold() for section in ('source_files', 'tables') for name in database[section]}
    for name in API_KEY_TABLES:
        if name.casefold() in dictionary_names:
            raise ValueError('Internal API key table must remain original: ' + name)
    output = pathlib.Path(outputPath)
    if output.exists():
        raise ValueError('Overlay output already exists')
    archives, archive_names = _mount(data_dir)
    template = None
    try:
        template = RawMPQ(str(templatePath), listfile=False)
        for name in API_KEY_TABLES:
            if template.get_hash_table_entry(name) is not None:
                raise ValueError('Asset template overrides an internal API key table: ' + name)
        current = {}
        skipped = {}
        for name in database['source_files']:
            try:
                current[name] = _effective(archives, name)
            except (ValueError, RuntimeError, NotImplementedError, OSError, struct.error) as error:
                current[name] = None
                skipped[name] = 'unreadable-source: ' + type(error).__name__
        same = all(current[name] is not None and digest(current[name]) == meta['source_sha256'] for name, meta in database['source_files'].items())
        if same:
            _write_exclusive(output, template_bytes)
            return dict(overlay_sha256=database['template_sha256'], fast_path=True, source_archives=archive_names,
                        matched_counts=database['reference_counts'], skipped={})
        files = {name: template.read_file(name) for name in database['fonts']}
        counts = {}
        for name, meta in database['source_files'].items():
            raw = current[name]
            if raw is None:
                skipped.setdefault(name, 'missing-source')
                continue
            if name in database['tables']:
                translated, matched, reason = _dbc(raw, database['tables'][name])
                if translated is not None:
                    files[name] = translated
                    counts[name] = matched
                else:
                    skipped[name] = reason
            elif digest(raw) == meta['source_sha256']:
                files[name] = template.read_file(name)
                counts[name] = meta.get('reference_changes', 1)
            elif name == 'Interface\\FrameXML\\GlobalStrings.lua':
                translated, matched = _globals(raw, database['global_assignments'])
                if translated is not None:
                    files[name] = translated
                    counts[name] = matched
                else:
                    skipped[name] = 'no-known-assignments'
            else:
                skipped[name] = 'changed-source-file'
        overlay_hash = _write_mpq(files, output)
        return dict(overlay_sha256=overlay_hash, fast_path=False, source_archives=archive_names,
                    matched_counts=counts, skipped=skipped, members=len(files))
    finally:
        if template is not None:
            template.file.close()
        for archive in archives:
            archive.file.close()


if __name__ == '__main__':
    raise SystemExit('This module is used by the Korean patch installer.')
