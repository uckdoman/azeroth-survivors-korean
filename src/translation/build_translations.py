"""Extract a reusable database only from text already applied by the Korean patch."""
import collections
import base64
import json
import pathlib
import re
import shutil
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent
WORK = ROOT.parent
PREVIOUS = WORK / 'azeroth-0.71.4'
shutil.copyfile(WORK / 'localization-runtime/rust_fmt_template.py', ROOT / 'rust_fmt_template.py')
from translator import sha, metadata_context, code_context, memory_copy_call, iterator_bound_reference, FORMAT_DISPLAY_OVERRIDES, parse_template, Cs, CS_ARCH_X86, CS_MODE_64, pefile

read = lambda p: json.loads(p.read_text(encoding='utf-8'))
source = (PREVIOUS / 'AzerothSurvivors.original.exe').read_bytes()
pe = pefile.PE(data=source, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
code = source[text.PointerToRawData:text.PointerToRawData + text.SizeOfRawData]
cb = base + text.VirtualAddress
cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True
report = read(PREVIOUS / 'patch-report.json')
direct = {int(x['code_address'], 16): x for x in read(PREVIOUS / 'binary-map/direct-ui-strings.json')}
race_classes = read(WORK / 'wow-korean-terms/class_race_map.json')
protected = set(race_classes) | {'Male', 'Female'}
protected.update(x['source'] for x in read(PREVIOUS / 'binary-map/protected-name-refs.json'))
variants = collections.defaultdict(set)
for row in report['patches']:
    if row['kind'] in ('str', 'code', 'fmt'):
        variants[row['english']].add(row['korean'])
protected.update(english for english, translations in variants.items() if len(translations) != 1)
entries = {}
profile_patches = []
for patch in report['patches']:
    kind = patch['kind']
    if kind not in ('str', 'code', 'fmt'):
        continue
    row = dict(patch)
    if kind in ('code', 'fmt'):
        row['address'] = int(row['address'], 16)
    if kind == 'code':
        assert row['address'] in direct
        row['length_address'] = int(direct[row['address']]['length_address'], 16)
    profile_patches.append(row)
    english = patch['english']
    korean = patch['korean']
    if english in protected or english == korean:
        continue
    if english not in FORMAT_DISPLAY_OVERRIDES or korean != FORMAT_DISPLAY_OVERRIDES[english]:
        assert re.findall(r'\{[^{}]*\}', english) == re.findall(r'\{[^{}]*\}', korean), english
    entry = entries.setdefault(english, {'korean': korean, 'metadata_contexts': [], 'direct_contexts': [], 'format_contexts': [], 'owned_copy_contexts': [], 'iterator_bound_contexts': []})
    if kind == 'str':
        signature = metadata_context(source, pe, patch['offset'])
        entry['metadata_contexts'].append(signature)
    else:
        signature = code_context(cs, code, row['address'] - cb, row['address'])
        entry['direct_contexts' if kind == 'code' else 'format_contexts'].append(signature)
        if kind == 'code' and memory_copy_call(cs, pe, source, row['address']):
            entry['owned_copy_contexts'].append(signature)
        if kind == 'fmt' and iterator_bound_reference(cs, pe, source, row['address']):
            entry['iterator_bound_contexts'].append(signature)
for entry in entries.values():
    for kind in ('metadata_contexts', 'direct_contexts', 'format_contexts', 'owned_copy_contexts', 'iterator_bound_contexts'):
        entry[kind] = sorted(set(entry[kind]))
extra_contexts = ROOT / 'display-context-overrides.json'
if extra_contexts.exists():
    for english, signatures in read(extra_contexts).items():
        entries[english]['metadata_contexts'] = sorted(set(entries[english]['metadata_contexts'] + signatures))
for english, korean in FORMAT_DISPLAY_OVERRIDES.items():
    entries[english]['korean'] = korean
scripts = [{'original': row['original'], 'translated': row['translated']} for row in read(PREVIOUS / 'assets/injected-lua-rewrites.json')]
native = bytearray((PREVIOUS / 'testgame/AzerothSurvivors_KO.exe').read_bytes().replace(b'https://patch.invalid', b'https://wow.aethus.pl'))
native_pe = pefile.PE(data=bytes(native), fast_load=True)
skipped_owned = []
skipped_iterator_bounds = []
for patch in profile_patches:
    if patch['kind'] == 'fmt':
        bound = iterator_bound_reference(cs, pe, source, patch['address'])
        if bound:
            at = pe.get_offset_from_rva(patch['address'] - base)
            native[at + 3:at + 7] = source[at + 3:at + 7]
            skipped_iterator_bounds.append({'address': hex(patch['address']), 'english': patch['english'], **bound})
        elif patch['english'] in FORMAT_DISPLAY_OVERRIDES:
            at = pe.get_offset_from_rva(patch['address'] - base)
            original_target = patch['address'] + 7 + struct.unpack_from('<i', source, at + 3)[0]
            pieces, _ = parse_template(source, pe.get_offset_from_rva(original_target - base))
            placeholders = [piece.raw for piece in pieces if piece.kind == 'placeholder']
            assert len(placeholders) == 2 and placeholders[0] == b'\xc0'
            target = patch['address'] + 7 + struct.unpack_from('<i', native, at + 3)[0]
            target_at = native_pe.get_offset_from_rva(target - base)
            native[target_at:target_at + 2] = placeholders[0] + b'\0'
        continue
    if patch['kind'] != 'code' or len(patch['english'].encode('utf-8')) == len(patch['korean'].encode('utf-8')) or not memory_copy_call(cs, pe, source, patch['address']):
        continue
    at = pe.get_offset_from_rva(patch['address'] - base)
    native[at + 3:at + 7] = source[at + 3:at + 7]
    length_at = pe.get_offset_from_rva(patch['length_address'] - base)
    ins = next(cs.disasm(source[length_at:length_at + 16], patch['length_address']))
    imm = length_at + ins.imm_offset
    native[imm:imm + ins.imm_size] = source[imm:imm + ins.imm_size]
    skipped_owned.append({'address': hex(patch['address']), 'english': patch['english']})
expected_output = sha(native)
fields = []
for patch in report['patches']:
    kind = patch['kind']
    if kind in ('str', 'lua'):
        fields.append((patch['offset'], patch['offset'] + 16))
    elif kind in ('code', 'fmt'):
        address = int(patch['address'], 16)
        at = pe.get_offset_from_rva(address - base)
        fields.append((at + 3, at + 7))
        if kind == 'code':
            length_address = int(direct[address]['length_address'], 16)
            length_at = pe.get_offset_from_rva(length_address - base)
            ins = next(cs.disasm(source[length_at:length_at + 16], length_address))
            fields.append((length_at + ins.imm_offset, length_at + ins.imm_offset + ins.imm_size))
    elif kind == 'inline-owned-string':
        inline = next(x for x in read(PREVIOUS / 'binary-map/inline-owned-strings.json') if x['source'] == patch['english'])
        fields.append((inline['source_offset'], inline['source_offset'] + inline['byte_length']))
        at = pe.get_offset_from_rva(inline['tail_instruction_address'] - base)
        ins = next(cs.disasm(source[at:at + 16], inline['tail_instruction_address']))
        fields.append((at + ins.imm_offset, at + ins.imm_offset + ins.imm_size))
for at, size in [(pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'), 2),
                 (pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'), 4),
                 (pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfInitializedData'), 4),
                 (pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'), 4),
                 (pe.sections[-1].get_file_offset() + 40, 40)]:
    fields.append((at, at + size))
merged = []
for left, right in sorted(fields):
    if merged and left <= merged[-1][1]:
        merged[-1][1] = max(right, merged[-1][1])
    else:
        merged.append([left, right])
delta = [{'offset': left, 'before_hex': source[left:right].hex(), 'after_base64': base64.b64encode(native[left:right]).decode()}
         for left, right in merged if source[left:right] != native[left:right]]
kind_map = {'str': 'metadata', 'code': 'direct', 'fmt': 'format', 'lua': 'scripts', 'inline-owned-string': 'inline'}
matched_counts = dict(collections.Counter(kind_map[p['kind']] for p in report['patches']))
matched_counts['direct'] -= len(skipped_owned)
matched_counts['format'] -= len(skipped_iterator_bounds)
profile = {'delta': delta, 'append_base64': base64.b64encode(native[len(source):]).decode(),
           'matched_counts': matched_counts, 'expected_output_sha256': expected_output,
           'skipped_owned_strings': skipped_owned, 'owned_copy_safe': True,
           'skipped_iterator_bounds': skipped_iterator_bounds, 'iterator_bounds_safe': True}
database = {'schema': 1, 'translations': dict(sorted(entries.items())), 'protected': sorted(protected),
            'max_text_bytes': max(len(english.encode('utf-8')) for english in entries), 'scripts': scripts,
            'profiles': {sha(source): profile}}
(ROOT / 'translations.json').write_text(json.dumps(database, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
print(json.dumps({'database_entries': len(entries), 'exact_profile_references': len(profile_patches), 'whole_scripts': len(scripts), 'database_bytes': (ROOT / 'translations.json').stat().st_size, 'skipped_owned_count': len(skipped_owned), 'skipped_iterator_bounds': skipped_iterator_bounds, 'profile_output_sha256': expected_output}))
