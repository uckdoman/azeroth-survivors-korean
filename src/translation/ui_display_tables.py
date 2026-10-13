"""Source-gated Korean race views for two proven UI callers only.

The original race table, enum getter, lookup table, and English parser are kept.
The caller supplies an 8-byte-aligned append callback accepting bytes or a
callable(upcoming_va). It must register the returned DIR64 RVAs and make the
appended getter executable. This module never writes a file or runs a game.
"""
import hashlib
import struct


def _number(value):
    return int(value, 0) if isinstance(value, str) else value


def _dir64_rvas(source, pe):
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    start = pe.get_offset_from_rva(directory.VirtualAddress)
    end = start + directory.Size
    result = set()
    while start < end:
        page, size = struct.unpack_from('<II', source, start)
        if not page and not size:
            break
        assert size >= 8 and size % 4 == 0 and start + size <= end
        for (entry,) in struct.iter_unpack('<H', source[start + 8:start + size]):
            if entry >> 12 == 10:
                result.add(page + (entry & 0xfff))
        start += size
    return result


def apply_display_table_bindings(source, data, pe, store_aligned, bindings):
    source_hash = hashlib.sha256(source).hexdigest()
    image_base = pe.OPTIONAL_HEADER.ImageBase
    applied, relocations = [], []
    for binding in bindings:
        if binding['source_sha256'] != source_hash:
            continue
        assert binding['kind'] == 'race_ui_shadow'
        table_offset = _number(binding['table_file_offset'])
        table_rva = pe.get_rva_from_offset(table_offset)
        table_va = image_base + table_rva
        assert table_rva == _number(binding['table_rva'])
        assert binding['row_bytes'] == 88 and binding['row_count'] == 8
        table_size = 88 * 8
        original_table = source[table_offset:table_offset + table_size]
        assert hashlib.sha256(original_table).hexdigest() == binding['table_sha256']
        assert data[table_offset:table_offset + table_size] == original_table
        original_relocations = _dir64_rvas(source, pe)
        slots = [row * 88 + offset for row in range(8)
                 for offset in (0, 16, 32, 48, 64)]
        assert sorted(rva - table_rva for rva in original_relocations
                      if table_rva <= rva < table_rva + table_size) == slots
        shadow = bytearray(original_table)
        assert len(binding['names']) == 8
        names = []
        for row, name in enumerate(binding['names']):
            pointer, length = struct.unpack_from('<QQ', original_table, row * 88)
            text_offset = pe.get_offset_from_rva(pointer - image_base)
            english = name['english'].encode('utf-8')
            assert length == len(english)
            assert source[text_offset:text_offset + length] == english
            assert data[text_offset:text_offset + length] == english
            korean = name['korean'].encode('utf-8')
            korean_pointer = store_aligned(korean)
            assert korean_pointer % 8 == 0
            struct.pack_into('<QQ', shadow, row * 88, korean_pointer, len(korean))
            assert shadow[row * 88 + 16:(row + 1) * 88] == original_table[row * 88 + 16:(row + 1) * 88]
            names.append({'english': name['english'], 'korean': name['korean'],
                          'pointer': korean_pointer, 'length': len(korean)})
        shadow_va = store_aligned(bytes(shadow))
        assert shadow_va % 8 == 0
        lookup_va = _number(binding['lookup_address'])
        lookup_offset = pe.get_offset_from_rva(lookup_va - image_base)
        original_lookup = source[lookup_offset:lookup_offset + 7 * 8]
        assert original_lookup.hex() == binding['lookup_before_hex']
        assert data[lookup_offset:lookup_offset + 56] == original_lookup
        assert list(struct.unpack('<7Q', original_lookup)) == [table_va + row * 88 for row in range(1, 8)]
        shadow_lookup = struct.pack('<7Q', *(shadow_va + row * 88 for row in range(1, 8)))
        shadow_lookup_va = store_aligned(shadow_lookup)
        assert shadow_lookup_va % 8 == 0
        getter_va = _number(binding['getter_address'])
        getter_offset = pe.get_offset_from_rva(getter_va - image_base)
        getter = source[getter_offset:getter_offset + 32]
        assert getter.hex() == binding['getter_before_hex']
        assert data[getter_offset:getter_offset + 32] == getter
        # Exact 31-byte leaf: only internal short JA, two RIP LEAs, two RETs.
        assert getter[:11].hex() == '80c1fe80f906770f0fb6c1'
        assert getter[11:14].hex() == '488d0d'
        assert getter[18:23].hex() == '488b04c1c3'
        assert getter[23:26].hex() == '488d05'
        assert getter[30:] == b'\xc3\xcc'
        assert getter_va + 18 + struct.unpack_from('<i', getter, 14)[0] == lookup_va
        assert getter_va + 30 + struct.unpack_from('<i', getter, 26)[0] == table_va

        def relocated_getter(upcoming_va):
            patched = bytearray(getter)
            struct.pack_into('<i', patched, 14, shadow_lookup_va - (upcoming_va + 18))
            struct.pack_into('<i', patched, 26, shadow_va - (upcoming_va + 30))
            assert all(patched[index] == getter[index] for index in range(32)
                       if not (14 <= index < 18 or 26 <= index < 30))
            return bytes(patched)

        ui_getter_va = store_aligned(relocated_getter)
        assert ui_getter_va % 8 == 0
        calls = []
        for caller in binding['ui_calls']:
            address = _number(caller['address'])
            offset = pe.get_offset_from_rva(address - image_base)
            before = bytes.fromhex(caller['before_hex'])
            assert len(before) == 5 and before[0] == 0xe8
            assert source[offset:offset + 5] == data[offset:offset + 5] == before
            assert address + 5 + struct.unpack_from('<i', before, 1)[0] == getter_va
            after = b'\xe8' + struct.pack('<i', ui_getter_va - (address + 5))
            data[offset:offset + 5] = after
            calls.append({'address': address, 'before_hex': before.hex(), 'after_hex': after.hex()})
        assert len(calls) == 2
        # There are no extra approved LEAs in this source-gated binding.
        assert not binding.get('ui_leas')
        new_rvas = [shadow_va - image_base + offset for offset in slots]
        new_rvas += [shadow_lookup_va - image_base + offset for offset in range(0, 56, 8)]
        assert len(new_rvas) == len(set(new_rvas)) == 47
        relocations.extend(new_rvas)
        assert data[table_offset:table_offset + table_size] == original_table
        assert data[lookup_offset:lookup_offset + 56] == original_lookup
        assert data[getter_offset:getter_offset + 32] == getter
        applied.append({'kind': binding['kind'], 'source_sha256': source_hash,
                        'original_table_sha256': binding['table_sha256'],
                        'original_table_address': table_va,
                        'original_lookup_address': lookup_va, 'original_getter_address': getter_va,
                        'shadow_table_pointer': shadow_va, 'shadow_lookup_pointer': shadow_lookup_va,
                        'ui_getter_pointer': ui_getter_va,
                        'ui_getter_hex': relocated_getter(ui_getter_va).hex(),
                        'names': names, 'calls': calls, 'ui_leas': [],
                        'new_dir64_count': len(new_rvas), 'canonical_table_getter_lookup_unchanged': True,
                        'english_parser_unchanged': True})
    return applied, relocations
