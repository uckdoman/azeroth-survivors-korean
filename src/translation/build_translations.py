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
from translator import sha, metadata_context, code_context, memory_copy_call, iterator_bound_reference, FORMAT_DISPLAY_OVERRIDES, display_template_override, parse_template, Cs, CS_ARCH_X86, CS_MODE_64, pefile

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
ui_values = ROOT / 'ui-translations.json'
ui_contexts = ROOT / 'ui-display-contexts.json'
if ui_values.exists() and ui_contexts.exists():
    display = read(ui_contexts)
    for english, korean in read(ui_values).items():
        if english not in FORMAT_DISPLAY_OVERRIDES or korean != FORMAT_DISPLAY_OVERRIDES[english]:
            assert re.findall(r'\{[^{}]*\}', english) == re.findall(r'\{[^{}]*\}', korean), english
        entry = entries.setdefault(english, {'korean': korean, 'metadata_contexts': [], 'direct_contexts': [],
            'format_contexts': [], 'owned_copy_contexts': [], 'iterator_bound_contexts': []})
        entry['display_sources'] = [display['source_sha256']]
        entry['display_contexts'] = {kind: display.get(kind, {}).get(english, []) for kind in ('metadata', 'direct', 'format')}
        entry['display_references'] = {kind: display['references'][kind].get(english, []) for kind in ('metadata', 'direct', 'format')}
        entry['display_reference_values'] = {kind: display['reference_values'][kind].get(english, {}) for kind in ('metadata', 'direct', 'format')}
extra_ui_path = ROOT / 'ui-display-builds.json'
extra_ui = read(extra_ui_path)['sources'] if extra_ui_path.exists() else {}
for build_hash, build in extra_ui.items():
    assert re.fullmatch(r'[0-9a-f]{64}', build_hash)
    for english, display in build['entries'].items():
        assert english in entries, 'Unregistered translation: ' + english
        for kind, values in display.get('reference_values', {}).items():
            assert kind in ('metadata', 'direct', 'format')
            for korean in values.values():
                if FORMAT_DISPLAY_OVERRIDES.get(english) != korean:
                    assert re.findall(r'\{[^{}]*\}', english) == re.findall(r'\{[^{}]*\}', korean), english
        entries[english].setdefault('display_builds', {})[build_hash] = display
scripts = [{'original': row['original'], 'translated': row['translated']} for row in read(PREVIOUS / 'assets/injected-lua-rewrites.json')]
short_guard_config = read(ROOT / 'short-string-guards.json')
short_guards = short_guard_config['sources'].get(sha(source), [])
assert short_guards
assert all(entries[name]['korean'].encode('utf-8') for name in short_guard_config['sensitive_metadata'])
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
            rebuilt = display_template_override(patch['english'], FORMAT_DISPLAY_OVERRIDES[patch['english']], pieces)
            target = patch['address'] + 7 + struct.unpack_from('<i', native, at + 3)[0]
            target_at = native_pe.get_offset_from_rva(target - base)
            old_pieces, old_end = parse_template(native, target_at)
            assert len(rebuilt) <= old_end - target_at
            native[target_at:target_at + len(rebuilt)] = rebuilt
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
from ui_bindings import apply_short_string_guards, apply_bindings
applied_short_guards = apply_short_string_guards(source, native, pe, short_guards)
owned_config = read(ROOT / 'owned-string-bindings.json')
owned_bindings = owned_config['sources'].get(sha(source), [])
native_korean = next(s for s in native_pe.sections if s.Name.rstrip(b'\0') == b'.korean')

def existing_payload(raw):
    at = native.find(raw + b'\0', native_korean.PointerToRawData,
        native_korean.PointerToRawData + native_korean.SizeOfRawData)
    assert at >= native_korean.PointerToRawData, 'Missing audited Korean payload'
    return base + native_pe.get_rva_from_offset(at)

applied_owned = apply_bindings(source, native, pe, existing_payload, owned_bindings)
owned_addresses = {hex(row['pointer_address']) for row in owned_bindings}
skipped_owned = [row for row in skipped_owned if row['address'] not in owned_addresses]
expected_output = sha(native)
fields = []
for row in owned_bindings:
    at = pe.get_offset_from_rva(row['pointer_address'] - base)
    fields.append((at + 3, at + 7))
    for field in row['size_fields']:
        at = pe.get_offset_from_rva(field['address'] - base) + field['immediate_offset']
        fields.append((at, at + field['immediate_size']))
for guard in short_guards:
    at = pe.get_offset_from_rva(guard['address'] - base)
    fields.append((at, at + len(bytes.fromhex(guard['before_hex']))))
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
           'skipped_iterator_bounds': skipped_iterator_bounds, 'iterator_bounds_safe': True,
           'short_strings_safe': True, 'applied_short_string_guards': applied_short_guards,
           'applied_owned_strings': applied_owned}
database = {'schema': 1, 'translations': dict(sorted(entries.items())), 'protected': sorted(protected),
            'max_text_bytes': max(len(english.encode('utf-8')) for english in entries), 'scripts': scripts,
            'profiles': {sha(source): profile}, 'short_string_guards': short_guard_config['sources'],
            'short_string_sensitive_metadata': short_guard_config['sensitive_metadata'],
            'owned_string_bindings': owned_config['sources']}
ui_bindings = ROOT / 'ui-bindings.json'
if ui_bindings.exists():
    bindings = read(ui_bindings)
    database['ui_bindings'] = {bindings['source_sha256']: bindings['bindings']}
for build_hash, build in extra_ui.items():
    if build.get('bindings'):
        assert build_hash not in database.get('ui_bindings', {})
        database.setdefault('ui_bindings', {})[build_hash] = build['bindings']
(ROOT / 'translations.json').write_text(json.dumps(database, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
print(json.dumps({'database_entries': len(entries), 'exact_profile_references': len(profile_patches), 'whole_scripts': len(scripts), 'database_bytes': (ROOT / 'translations.json').stat().st_size, 'skipped_owned_count': len(skipped_owned), 'skipped_iterator_bounds': skipped_iterator_bounds, 'profile_output_sha256': expected_output}))
