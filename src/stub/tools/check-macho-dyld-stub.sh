#!/bin/bash
# Sanity check of the generated macOS arm64 dyld-format stub headers:
#   arm64-darwin.macho-dyld-entry.h  ELF64 AArch64 relocatable (for ElfLinker)
#   arm64-darwin.macho-dyld-fold.h   flat code, AArch64 "b" at offset 0, <= 16 KiB
set -eu
d="$(dirname "$0")/.."
for f in arm64-darwin.macho-dyld-entry.h arm64-darwin.macho-dyld-fold.h; do
    [ -f "$d/$f" ] || { echo "missing $f"; exit 1; }
done
python3 - "$d/arm64-darwin.macho-dyld-entry.h" "$d/arm64-darwin.macho-dyld-fold.h" <<'PY'
import re, sys
def blob(path):  # bin2h: decimal bytes, "/* 0x.... */" offset comments
    src = open(path).read()
    body = re.sub(r'/\*.*?\*/', '', src[src.index('] = {') + 5:src.rindex('}')], flags=re.S)
    data = bytes(int(x) for x in body.replace('\n', ' ').split(',') if x.strip())
    n = int(re.search(r'\[(\d+)\] = \{', src).group(1))
    assert len(data) == n, f'{path}: parsed {len(data)} of {n} bytes'
    return data
entry, fold = blob(sys.argv[1]), blob(sys.argv[2])
assert entry[:4] == b'\x7fELF' and entry[4] == 2 and int.from_bytes(entry[18:20], 'little') == 183, 'entry is not ELF64 AArch64'
assert int.from_bytes(entry[16:18], 'little') == 1, 'entry is not ET_REL'
assert len(fold) <= 16384, f'fold too large: {len(fold)}'
insn = int.from_bytes(fold[0:4], 'little')
assert insn >> 26 == 0b000101, f'fold offset 0 is not a b: {insn:08x}'
print(f'OK (entry {len(entry)} bytes ELF, fold {len(fold)} bytes)')
PY
