import hashlib
import json
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'analysis-deps'))
import mpyq

ASSIGNMENT = re.compile(rb'''(?m)^([A-Z_][A-Z0-9_]*)[ \t]*=[ \t]*("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*')''')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(archive, name):
    entry = archive.get_hash_table_entry(name)
    if entry is None:
        raise ValueError('Missing template member: ' + name)
    block = archive.block_table[entry.block_table_index]
    if block.flags != 0x80000000 or block.size != block.archived_size:
        raise ValueError('Template is not the confirmed raw MPQ format')
    archive.file.seek(archive.header['offset'] + block.offset)
    raw = archive.file.read(block.archived_size)
    if len(raw) != block.size:
        raise ValueError('Truncated template member')
    return raw


def string(pool, offset):
    if offset >= len(pool):
        raise ValueError('Bad reference DBC string')
    end = pool.find(b'\0', offset)
    if end < 0:
        raise ValueError('Unterminated reference DBC string')
    return pool[offset:end].decode('utf-8')


def build():
    old = ROOT.parent / 'azeroth-latest'
    template_path = ROOT.parent / 'azeroth-0.71.4' / 'testgame' / 'Data' / 'patch-Z.MPQ'
    report = json.loads((old / 'dbc-patch-report.json').read_text(encoding='utf-8'))
    archive = mpyq.MPQArchive(str(template_path), listfile=False)
    database = dict(schema=1, template_sha256=digest(template_path.read_bytes()), fonts=[], source_files={},
                    tables={}, global_assignments={}, reference_counts={})
    ambiguities = 0
    try:
        names = read(archive, '(listfile)').decode('utf-8').splitlines()
        for name in names:
            if name == '(listfile)':
                continue
            korean_data = read(archive, name)
            if name.lower().startswith('fonts\\'):
                database['fonts'].append(name)
                continue
            original_path = old / 'assets' / 'effective' / pathlib.Path(*name.split('\\'))
            if not original_path.is_file():
                raise ValueError('Missing confirmed English source: ' + name)
            original = original_path.read_bytes()
            database['source_files'][name] = dict(source_sha256=digest(original))
            if name.lower().endswith('.dbc'):
                table = pathlib.PureWindowsPath(name).name
                schema = report[table]
                magic, rows, fields, width, pool_size = struct.unpack_from('<4s4I', original)
                ko_magic, ko_rows, ko_fields, ko_width, ko_pool_size = struct.unpack_from('<4s4I', korean_data)
                if (magic, rows, fields, width) != (ko_magic, ko_rows, ko_fields, ko_width) or magic != b'WDBC' or width != fields * 4:
                    raise ValueError('Reference DBC schema differs: ' + name)
                if digest(original) != schema['source_sha256'] or digest(korean_data) != schema['output_sha256']:
                    raise ValueError('Reference DBC differs from confirmed translation: ' + name)
                pool_start = 20 + rows * width
                old_pool, ko_pool = original[pool_start:], korean_data[pool_start:]
                if len(old_pool) != pool_size or len(ko_pool) != ko_pool_size:
                    raise ValueError('Reference DBC pool size differs')
                columns = {}
                for column in schema['columns']:
                    mapping, conflicted = {}, set()
                    for index in range(rows):
                        pos = 20 + index * width + column * 4
                        english = string(old_pool, struct.unpack_from('<I', original, pos)[0])
                        korean = string(ko_pool, struct.unpack_from('<I', korean_data, pos)[0])
                        if not english or not korean or english == korean:
                            continue
                        if english in mapping and mapping[english] != korean:
                            conflicted.add(english)
                        mapping[english] = korean
                    for english in conflicted:
                        mapping.pop(english, None)
                    ambiguities += len(conflicted)
                    columns[str(column)] = mapping
                database['tables'][name] = dict(field_count=fields, record_width=width, string_columns=columns)
                database['reference_counts'][name] = schema['changes']
            else:
                database['source_files'][name]['reference_changes'] = 1
                database['reference_counts'][name] = 1
                if name == 'Interface\\FrameXML\\GlobalStrings.lua':
                    def assignments(raw):
                        values, ambiguous = {}, set()
                        for match in ASSIGNMENT.finditer(raw):
                            key = match.group(1).decode('ascii')
                            literal = match.group(2).decode('utf-8')
                            if key in values and values[key] != literal:
                                ambiguous.add(key)
                            values[key] = literal
                        return {key: value for key, value in values.items() if key not in ambiguous}
                    english_values, korean_values = assignments(original), assignments(korean_data)
                    database['global_assignments'] = {
                        key: dict(english_literal=english, korean_literal=korean_values[key])
                        for key, english in english_values.items() if key in korean_values and english != korean_values[key]
                    }
        output = ROOT / 'asset_translations.json'
        output.write_text(json.dumps(database, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
        print(json.dumps(dict(file=str(output), bytes=output.stat().st_size, tables=len(database['tables']),
                              source_files=len(database['source_files']), assignments=len(database['global_assignments']),
                              ambiguous_pairs_omitted=ambiguities, template_sha256=database['template_sha256']), ensure_ascii=False))
    finally:
        archive.file.close()


if __name__ == '__main__':
    build()
