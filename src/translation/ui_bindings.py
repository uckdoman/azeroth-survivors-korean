"""Apply audited UI string bindings for one exact source build."""
import struct


def apply_short_string_guards(source, data, pe, guards):
    """Use the existing byte loop when a compiler-specialized SIMD prefix is empty."""
    base = pe.OPTIONAL_HEADER.ImageBase
    applied = []
    for row in guards:
        for check in row['guards']:
            at = pe.get_offset_from_rva(check['address'] - base)
            expected = bytes.fromhex(check['before_hex'])
            assert source[at:at + len(expected)] == expected
        address = row['address']
        at = pe.get_offset_from_rva(address - base)
        before = bytes.fromhex(row['before_hex'])
        assert source[at:at + len(before)] == before
        assert data[at:at + len(before)] == before
        target = row['scalar_address']
        if len(before) == 5:
            displacement = target - (address + 5)
            assert -128 <= displacement <= 127
            replacement = b'\x48\x85\xc0\x74' + struct.pack('b', displacement)
        else:
            assert len(before) >= 9
            replacement = b'\x48\x85\xc0\x0f\x84' + struct.pack('<i', target - (address + 9))
            replacement += b'\x90' * (len(before) - len(replacement))
        assert len(replacement) == len(before)
        data[at:at + len(before)] = replacement
        applied.append({'address': hex(address), 'scalar_address': hex(target)})
    return applied


def apply_bindings(source, data, pe, store, bindings):
    base = pe.OPTIONAL_HEADER.ImageBase
    applied = []
    offset = lambda address: pe.get_offset_from_rva(address - base)

    def gate(address, raw):
        at = offset(address)
        expected = bytes.fromhex(raw)
        assert source[at:at + len(expected)] == expected, hex(address)
        return at

    def immediate(field, value):
        at = gate(field['address'], field['before_hex'])
        start = at + field['immediate_offset']
        size = field['immediate_size']
        assert data[start:start + size] == source[start:start + size]
        data[start:start + size] = value.to_bytes(size, 'little')

    for row in bindings:
        for check in row['guards']:
            gate(check['address'], check['before_hex'])
        raw = row['korean'].encode('utf-8')
        kind = row['kind']
        if kind == 'owned_memcpy':
            old = row['english'].encode('utf-8')
            assert raw and len(raw) < 0x80000000
            assert {'allocation', 'capacity', 'length', 'copy_length', 'oom'} == {f['role'] for f in row['size_fields']}
            address = row['pointer_address']
            at = gate(address, row['pointer_before_hex'])
            assert bytes.fromhex(row['pointer_before_hex'])[:3] == b'\x48\x8d\x15'
            assert len(bytes.fromhex(row['pointer_before_hex'])) == 7
            old_target = address + 7 + struct.unpack_from('<i', source, at + 3)[0]
            text_at = offset(old_target)
            assert source[text_at:text_at + len(old)] == old
            for field in row['size_fields']:
                before = bytes.fromhex(field['before_hex'])
                start, size = field['immediate_offset'], field['immediate_size']
                assert int.from_bytes(before[start:start + size], 'little') == len(old)
                immediate(field, len(raw))
            assert data[at + 3:at + 7] == source[at + 3:at + 7]
            data[at + 3:at + 7] = struct.pack('<i', store(raw) - (address + 7))
        elif kind in ('borrowed', 'same_byte_span'):
            address = row['pointer_address']
            at = gate(address, row['pointer_before_hex'])
            assert len(bytes.fromhex(row['pointer_before_hex'])) == 7
            old_target = address + 7 + struct.unpack_from('<i', source, at + 3)[0]
            text_at = offset(old_target)
            old = row['english'].encode('utf-8')
            assert source[text_at:text_at + len(old)] == old
            if kind == 'same_byte_span':
                assert len(raw) == len(old)
            else:
                immediate(row['length'], len(raw))
            assert data[at + 3:at + 7] == source[at + 3:at + 7]
            data[at + 3:at + 7] = struct.pack('<i', store(raw) - (address + 7))
        elif kind == 'owned_title_sse':
            assert len(raw) <= 16
            address = row['copy_address']
            at = gate(address, row['copy_before_hex'])
            old_copy = bytes.fromhex(row['copy_before_hex'])
            assert len(old_copy) == 20 and old_copy[:2] == b'\x48\xb9'
            assert old_copy[10:16] == b'\x48\x89\x08\xc7\x40\x07'
            assert data[at:at + 20] == old_copy
            payload = store(raw.ljust(16, b'\0'))
            # Preserve RCX's original live-out literal; XMM0 is dead at these audited sites.
            code = old_copy[:10] + b'\x0f\x10\x05' + struct.pack('<i', payload - (address + 17)) + b'\x0f\x11\x00'
            assert len(code) == len(old_copy)
            data[at:at + 20] = code
            immediate(row['allocation'], 16)
            immediate(row['capacity'], 16)
            immediate(row['length'], len(raw))
            immediate(row['error_size'], 16)
        elif kind in ('owned_repoint', 'owned_readonly'):
            capacity = row['capacity_bytes']
            assert len(raw) <= capacity
            padded = raw.ljust(capacity, b'\0')
            payload = store(padded)
            for load in row['loads']:
                address = load['address']
                at = gate(address, load['before_hex'])
                start = at + load['displacement_offset']
                assert load['payload_offset'] + load['bytes_read'] <= capacity
                assert data[start:start + 4] == source[start:start + 4]
                data[start:start + 4] = struct.pack('<i', payload + load['payload_offset'] - (address + load['size']))
            if 'tail' in row:
                tail = row['tail']
                replacement = padded[tail['payload_offset']:tail['payload_offset'] + tail['immediate_size']]
                assert len(replacement) == tail['immediate_size']
                immediate(tail, int.from_bytes(replacement, 'little'))
            if 'length' in row:
                immediate(row['length'], len(raw))
        elif kind == 'inline_equal':
            old_size = row['bytes']
            assert len(raw) <= old_size
            padded = raw.ljust(old_size, b' ')
            for part in row['parts']:
                replacement = padded[part['payload_offset']:part['payload_offset'] + part['immediate_size']]
                assert len(replacement) == part['immediate_size']
                immediate(part, int.from_bytes(replacement, 'little'))
        elif kind == 'selected_gender':
            assert len(row['male'].encode('utf-8')) == len(row['female'].encode('utf-8')) == 6
            for name, english in [('male', 'Male'), ('female', 'Female')]:
                part = row[name + '_pointer']
                address = part['address']
                at = gate(address, part['before_hex'])
                target = address + 7 + struct.unpack_from('<i', source, at + 3)[0]
                text_at = offset(target)
                assert source[text_at:text_at + len(english)] == english.encode('ascii')
                assert data[at:at + 7] == source[at:at + 7]
                data[at + 3:at + 7] = struct.pack('<i', store(row[name].encode('utf-8')) - (address + 7))
            address = row['length_address']
            at = gate(address, row['length_before_hex'])
            assert bytes.fromhex(row['length_before_hex']) == b'\x48\x8d\x04\x45\x04\0\0\0'
            assert data[at:at + 8] == source[at:at + 8]
            data[at:at + 8] = b'\xb8\x06\0\0\0\x90\x90\x90'
        else:
            raise ValueError('Unsupported UI binding: ' + kind)
        applied.append({'kind': kind, 'english': row['english'], 'korean': row['korean']})
    return applied
