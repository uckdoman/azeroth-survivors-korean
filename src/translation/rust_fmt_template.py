"""Read/rebuild Rust core fmt packed templates; never edits an executable."""
from dataclasses import dataclass
import struct

@dataclass(frozen=True)
class Piece:
    kind: str
    raw: bytes
    text: str | None = None

def parse_template(data: bytes, start: int = 0, limit: int = 65536):
    cursor = start
    pieces = []
    while cursor - start < limit:
        at = cursor
        if cursor >= len(data):
            raise ValueError('unterminated template')
        tag = data[cursor]
        cursor += 1
        if tag == 0:
            return pieces, cursor
        if tag < 0x80:
            size = tag
            end = cursor + size
            text = data[cursor:end].decode('utf-8')
            if end > len(data):
                raise ValueError('truncated literal')
            cursor = end
            pieces.append(Piece('literal', data[at:cursor], text))
        elif tag == 0x80:
            if cursor + 2 > len(data):
                raise ValueError('truncated extended length')
            size = struct.unpack_from('<H', data, cursor)[0]
            cursor += 2
            end = cursor + size
            if end > len(data):
                raise ValueError('truncated long literal')
            text = data[cursor:end].decode('utf-8')
            cursor = end
            pieces.append(Piece('literal', data[at:cursor], text))
        elif tag >= 0xC0:
            # Field order: flags:u32, width:u16, precision:u16, arg_index:u16.
            size = 4 * bool(tag & 1) + 2 * bool(tag & 2) + 2 * bool(tag & 4) + 2 * bool(tag & 8)
            cursor += size
            if cursor > len(data):
                raise ValueError('truncated placeholder')
            pieces.append(Piece('placeholder', data[at:cursor]))
        else:
            raise ValueError(f'invalid tag 0x{tag:02x}')
    raise ValueError('template exceeds scan limit')

def encode_literal(text: str) -> bytes:
    result = bytearray()
    raw = text.encode('utf-8')
    cursor = 0
    while cursor < len(raw):
        end = min(cursor + 65535, len(raw))
        while end < len(raw) and raw[end] & 0xC0 == 0x80:
            end -= 1
        chunk = raw[cursor:end]
        result.extend(bytes([len(chunk)]) if len(chunk) < 128 else b'\x80' + struct.pack('<H',len(chunk)))
        result.extend(chunk)
        cursor = end
    return bytes(result)

def rebuild(pieces: list[Piece], translated_literals: dict[str, str]) -> bytes:
    data = b''.join(encode_literal(translated_literals.get(p.text, p.text)) if p.kind == 'literal' else p.raw for p in pieces) + b'\0'
    parsed, end = parse_template(data)
    assert end == len(data)
    assert [p.raw for p in parsed if p.kind == 'placeholder'] == [p.raw for p in pieces if p.kind == 'placeholder']
    return data

if __name__ == '__main__':
    from pathlib import Path
    source = Path(__file__).resolve().parent.parent / 'azeroth-ko/AzerothSurvivors.original.exe'
    data = source.read_bytes()
    for offset in [0x57ac648, 0x57ac6d1, 0x57d0fc0, 0x57b15b6]:
        pieces, end = parse_template(data, offset)
        assert rebuild(pieces, {}) == data[offset:end]
        print(hex(offset), [(p.kind, p.text if p.kind == 'literal' else p.raw.hex()) for p in pieces])
    # Exercise UTF-8 byte counts, the 127/128 boundary, chunking, and embedded zero bytes in tags.
    for text in ['가', 'a'*127, '가'*42+'ab', '가'*22000, 'x\0y', '']:
        raw = encode_literal(text) + b'\0'
        pieces, end = parse_template(raw, limit=len(raw)+1)
        assert ''.join(p.text for p in pieces) == text
        assert end == len(raw)
    original, _ = parse_template(b'\xc3\0\0\0\0\x05\0\x01X\0')
    assert rebuild(original, {'X':'가'}) == b'\xc3\0\0\0\0\x05\0\x03\xea\xb0\x80\0'
    print('Self-checks passed.')
