"""Apply known Korean text to the supplied game; never substitute a game build."""
import argparse
import base64
import hashlib
import json
import pathlib
import re
import shutil
import struct
import sys

if not getattr(sys, 'frozen', False):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / 'analysis-deps'))
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from rust_fmt_template import parse_template, encode_literal


def sha(data):
    return hashlib.sha256(data).hexdigest()


def metadata_context(data, pe, offset):
    left = max(0, offset - 64)
    right = min(len(data), offset + 80)
    buf = bytearray(data[left:right])
    base = pe.OPTIONAL_HEADER.ImageBase
    end = base + pe.OPTIONAL_HEADER.SizeOfImage
    anchors = []
    for at in range((-left) % 8, len(buf) - 7, 8):
        value = struct.unpack_from('<Q', buf, at)[0]
        if not base <= value < end:
            continue
        buf[at:at + 8] = b'PTRVALUE'
        if left + at + 16 > len(data):
            continue
        length = struct.unpack_from('<Q', data, left + at + 8)[0]
        if not 1 <= length <= 512:
            continue
        try:
            target = pe.get_offset_from_rva(value - base)
            raw = data[target:target + length]
            text = raw.decode('utf-8')
            if len(raw) == length and '\0' not in text:
                anchors.append([at, sha(raw)])
        except (ValueError, UnicodeDecodeError, pefile.PEFormatError):
            pass
    return sha(bytes(buf) + json.dumps(anchors, separators=(',', ':')).encode())


def code_context(cs, code, offset, address):
    result = []
    for ins in cs.disasm(code[offset:offset + 80], address):
        operands = []
        for op in ins.operands:
            if op.type == X86_OP_REG:
                operands.append(['reg', ins.reg_name(op.reg)])
            elif op.type == X86_OP_MEM:
                mem = op.mem
                operands.append(['mem', ins.reg_name(mem.base), ins.reg_name(mem.index),
                                 mem.scale, 0 if ins.reg_name(mem.base) == 'rip' else mem.disp])
            elif op.type == X86_OP_IMM:
                operands.append(['imm', 0 if ins.mnemonic in ('call', 'jmp') or ins.mnemonic.startswith('j') else op.imm])
        result.append([ins.mnemonic, operands])
        if ins.mnemonic in ('call', 'jmp', 'ret') or len(result) == 7:
            break
    return sha(json.dumps(result, separators=(',', ':')).encode())


def format_text(pieces):
    parts = []
    counter = 0
    for piece in pieces:
        if piece.kind == 'literal':
            parts.append(piece.text)
        else:
            parts.append('{' + str(counter) + '}')
            counter += 1
    return ''.join(parts)


def translate(input_path, output_path, db_path):
    input_path = pathlib.Path(input_path).resolve()
    output_path = pathlib.Path(output_path).resolve()
    if input_path == output_path:
        raise ValueError('입력 파일과 출력 파일은 달라야 합니다.')
    source = input_path.read_bytes()
    database = json.loads(pathlib.Path(db_path).read_text(encoding='utf-8'))
    pe = pefile.PE(data=source, fast_load=True)
    if pe.FILE_HEADER.Machine != 0x8664:
        raise ValueError('지원하지 않는 실행파일 형식입니다.')
    base = pe.OPTIONAL_HEADER.ImageBase
    rdata = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.rdata')
    text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    align = lambda n, a: (n + a - 1) // a * a
    new_rva = align(max(s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) for s in pe.sections), pe.OPTIONAL_HEADER.SectionAlignment)
    new_raw = align(len(source), pe.OPTIONAL_HEADER.FileAlignment)
    data = bytearray(source)
    payload = bytearray()
    intern = {}
    counts = {'metadata': 0, 'direct': 0, 'format': 0, 'scripts': 0, 'inline': 0}
    profile = database.get('profiles', {}).get(sha(source))
    known = database['translations']
    protected = set(database['protected'])
    relocations = set()
    relocation_section = next((s for s in pe.sections if s.Name.rstrip(b'\0') == b'.reloc'), None)
    if relocation_section:
        relocation_data = source[relocation_section.PointerToRawData:relocation_section.PointerToRawData + relocation_section.SizeOfRawData]
        cursor = 0
        while cursor + 8 <= len(relocation_data):
            page, size = struct.unpack_from('<II', relocation_data, cursor)
            if not page and not size:
                break
            if size < 8 or size % 2 or cursor + size > len(relocation_data):
                raise ValueError('실행파일 재배치 테이블 오류')
            for at in range(cursor + 8, cursor + size, 2):
                value = struct.unpack_from('<H', relocation_data, at)[0]
                if value >> 12 == 10:
                    relocations.add(page + (value & 0xfff))
            cursor += size

    def offset(address):
        return pe.get_offset_from_rva(address - base)

    def string_at(address, length):
        at = offset(address)
        raw = source[at:at + length]
        if len(raw) != length:
            raise ValueError('문자열 범위 오류')
        return raw.decode('utf-8')

    def store(raw):
        if raw not in intern:
            intern[raw] = base + new_rva + len(payload)
            payload.extend(raw + b'\0')
        return intern[raw]

    def replace_metadata(ref, english, korean, kind='metadata'):
        pointer, length = struct.unpack_from('<QQ', source, ref)
        assert string_at(pointer, length) == english
        raw = korean.encode('utf-8')
        data[ref:ref + 16] = struct.pack('<QQ', store(raw), len(raw))
        counts[kind] += 1

    def replace_direct(address, length_address, english, korean):
        at = offset(address)
        old_target = address + 7 + struct.unpack_from('<i', source, at + 3)[0]
        length_at = offset(length_address)
        ins = next(cs.disasm(source[length_at:length_at + 16], length_address))
        assert ins.mnemonic == 'mov' and ins.imm_size in (4, 8)
        assert string_at(old_target, ins.operands[1].imm) == english
        raw = korean.encode('utf-8')
        data[at + 3:at + 7] = struct.pack('<i', store(raw) - (address + 7))
        imm = length_at + ins.imm_offset
        data[imm:imm + ins.imm_size] = len(raw).to_bytes(ins.imm_size, 'little')
        counts['direct'] += 1

    def replace_format(address, english, korean):
        at = offset(address)
        old_target = address + 7 + struct.unpack_from('<i', source, at + 3)[0]
        pieces, _ = parse_template(source, offset(old_target))
        assert format_text(pieces) == english
        placeholders = [p.raw for p in pieces if p.kind == 'placeholder']
        assert re.findall(r'\{(\d+)\}', korean) == [str(i) for i in range(len(placeholders))]
        rebuilt = bytearray()
        for part in re.split(r'(\{\d+\})', korean):
            rebuilt.extend(placeholders[int(part[1:-1])] if re.fullmatch(r'\{\d+\}', part) else encode_literal(part))
        rebuilt.append(0)
        data[at + 3:at + 7] = struct.pack('<i', store(bytes(rebuilt)) - (address + 7))
        counts['format'] += 1

    if profile and 'delta' in profile:
        for row in profile['delta']:
            at = row['offset']
            before = bytes.fromhex(row['before_hex'])
            replacement = base64.b64decode(row['after_base64'], validate=True)
            assert source[at:at + len(before)] == before
            assert len(before) == len(replacement)
            data[at:at + len(before)] = replacement
        data.extend(base64.b64decode(profile['append_base64'], validate=True))
        assert sha(data) == profile['expected_output_sha256']
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(data)
        report = {'input_sha256': sha(source), 'output_sha256': sha(data), 'profile_matched': True,
                  'matched_counts': profile['matched_counts'], 'game_build_replaced': False,
                  'native_update_modified': False, 'unknown_text_translated': False}
        pathlib.Path(str(output_path) + '.translation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        return report
    if profile:
        for patch in profile['patches']:
            kind = patch['kind']
            if kind == 'str':
                replace_metadata(patch['offset'], patch['english'], patch['korean'])
            elif kind == 'code':
                replace_direct(patch['address'], patch['length_address'], patch['english'], patch['korean'])
            elif kind == 'fmt':
                replace_format(patch['address'], patch['english'], patch['korean'])
        for row in profile.get('inline', []):
            old = row['source'].encode('utf-8')
            translated = row['korean'].encode('utf-8')
            assert len(old) == len(translated) == row['byte_length']
            at = row['source_offset']
            assert source[at:at + len(old)] == old
            tail_at = offset(row['tail_instruction_address'])
            ins = next(cs.disasm(source[tail_at:tail_at + 16], row['tail_instruction_address']))
            assert ins.mnemonic == 'mov' and ins.imm_size == 4 and ins.operands[1].imm == int.from_bytes(old[16:], 'little')
            data[at:at + len(old)] = translated
            data[tail_at + ins.imm_offset:tail_at + ins.imm_offset + 4] = translated[16:]
            counts['inline'] += 1
    else:
        lo = rdata.PointerToRawData
        hi = min(len(source), lo + rdata.SizeOfRawData)
        vlow = base + rdata.VirtualAddress
        vhigh = vlow + rdata.SizeOfRawData
        for ref in range(lo, hi - 16, 8):
            if ref - lo + rdata.VirtualAddress not in relocations:
                continue
            pointer, length = struct.unpack_from('<QQ', source, ref)
            if not vlow <= pointer < vhigh or not 1 <= length <= database['max_text_bytes']:
                continue
            try:
                english = string_at(pointer, length)
            except (ValueError, UnicodeDecodeError, pefile.PEFormatError):
                continue
            row = known.get(english)
            if not row or english in protected:
                continue
            if metadata_context(source, pe, ref) in row['metadata_contexts']:
                replace_metadata(ref, english, row['korean'])
        code = source[text.PointerToRawData:text.PointerToRawData + text.SizeOfRawData]
        cb = base + text.VirtualAddress
        pattern = rb'(?=([\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....))'
        for match in re.finditer(pattern, code, re.S):
            address = cb + match.start()
            target = address + 7 + struct.unpack('<i', match[1][-4:])[0]
            if not vlow <= target < vhigh:
                continue
            signature = None
            insns = list(cs.disasm(code[match.start():match.start() + 80], address))
            if not insns or insns[0].mnemonic != 'lea':
                continue
            reg = insns[0].reg_name(insns[0].operands[0].reg)
            length_reg = {'rcx': ('edx', 'rdx'), 'rdx': ('r8d', 'r8'), 'r8': ('r9d', 'r9')}.get(reg)
            if length_reg:
                for ins in insns[1:7]:
                    if ins.mnemonic in ('call', 'jmp', 'ret'):
                        break
                    if ins.mnemonic != 'mov' or len(ins.operands) != 2 or ins.operands[0].type != X86_OP_REG or ins.operands[1].type != X86_OP_IMM:
                        continue
                    if ins.reg_name(ins.operands[0].reg) not in length_reg or not 1 <= ins.operands[1].imm <= database['max_text_bytes']:
                        continue
                    try:
                        english = string_at(target, ins.operands[1].imm)
                    except (ValueError, UnicodeDecodeError, pefile.PEFormatError):
                        break
                    row = known.get(english)
                    if row and english not in protected:
                        signature = code_context(cs, code, match.start(), address)
                        if signature in row['direct_contexts']:
                            replace_direct(address, ins.address, english, row['korean'])
                    break
            try:
                pieces, _ = parse_template(source, offset(target), limit=8192)
                english = format_text(pieces)
            except (ValueError, UnicodeDecodeError, struct.error, pefile.PEFormatError):
                continue
            row = known.get(english)
            if not row or english in protected or not row['format_contexts']:
                continue
            signature = signature or code_context(cs, code, match.start(), address)
            if signature in row['format_contexts']:
                replace_format(address, english, row['korean'])

    for script in database['scripts']:
        original = script['original'].encode('utf-8')
        cursor = rdata.PointerToRawData
        end = min(len(source), cursor + rdata.SizeOfRawData)
        while True:
            at = source.find(original, cursor, end)
            if at < 0:
                break
            cursor = at + len(original)
            pointer = base + pe.get_rva_from_offset(at)
            needle = struct.pack('<QQ', pointer, len(original))
            for match in re.finditer(re.escape(needle), source[rdata.PointerToRawData:end]):
                ref = rdata.PointerToRawData + match.start()
                if ref % 8 == 0 and ref - rdata.PointerToRawData + rdata.VirtualAddress in relocations:
                    replace_metadata(ref, script['original'], script['translated'], 'scripts')

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if payload:
        section_offset = pe.sections[-1].get_file_offset() + 40
        if section_offset + 40 > pe.OPTIONAL_HEADER.SizeOfHeaders:
            raise ValueError('번역 섹션을 추가할 공간이 없습니다.')
        raw_size = align(len(payload), pe.OPTIONAL_HEADER.FileAlignment)
        data.extend(b'\0' * (new_raw - len(data)))
        data.extend(payload)
        data.extend(b'\0' * (raw_size - len(payload)))
        existing_names = {s.Name.rstrip(b'\0') for s in pe.sections}
        name = b'.korean'
        if name in existing_names:
            name = next(('.kor' + str(i)).encode() for i in range(1, 9999) if ('.kor' + str(i)).encode() not in existing_names)
        data[section_offset:section_offset + 40] = struct.pack('<8sIIIIIIHHI', name, len(payload), new_rva, raw_size, new_raw, 0, 0, 0, 0, 0x40000040)
        struct.pack_into('<H', data, pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'), pe.FILE_HEADER.NumberOfSections + 1)
        struct.pack_into('<I', data, pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'), align(new_rva + len(payload), pe.OPTIONAL_HEADER.SectionAlignment))
        struct.pack_into('<I', data, pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfInitializedData'), pe.OPTIONAL_HEADER.SizeOfInitializedData + raw_size)
        struct.pack_into('<I', data, pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'), 0)
        output_path.write_bytes(data)
    else:
        shutil.copyfile(input_path, output_path)
    report = {'input_sha256': sha(source), 'output_sha256': sha(output_path.read_bytes()),
              'profile_matched': bool(profile), 'matched_counts': counts, 'game_build_replaced': False,
              'native_update_modified': False, 'unknown_text_translated': False}
    pathlib.Path(str(output_path) + '.translation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('input_exe')
    parser.add_argument('output_exe')
    parser.add_argument('translations_json')
    parser.add_argument('--data-dir')
    parser.add_argument('--overlay')
    parser.add_argument('--overlay-template')
    parser.add_argument('--asset-db')
    args = parser.parse_args()
    asset_options = [args.data_dir, args.overlay, args.overlay_template, args.asset_db]
    if any(asset_options) and not all(asset_options):
        parser.error('--data-dir, --overlay, --overlay-template, --asset-db must be supplied together')
    try:
        report = translate(args.input_exe, args.output_exe, args.translations_json)
        if all(asset_options):
            from asset_overlay import apply
            asset_report = apply(args.data_dir, args.overlay_template, args.asset_db, args.overlay)
            report['asset_report'] = asset_report
            report['overlay_sha256'] = asset_report['overlay_sha256']
            pathlib.Path(str(pathlib.Path(args.output_exe).resolve()) + '.translation.json').write_text(
                json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(report, ensure_ascii=True))
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
