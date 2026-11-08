/* macho_fat.h -- Mach-O universal ("fat") binaries for macho/arm64dyld

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.
 */

// Pure helpers (no I/O): parse/lay out/write a 32-bit fat header (big-endian
// fat_arch), and undo what `codesign` does to a slice that UPX left
// unpacked, so `upx -d` can rebuild the original universal file exactly.

#pragma once

namespace upx_macho_fat {

constexpr unsigned MAX_SLICES = 8;

struct Slice {
    unsigned cputype, cpusubtype, offset, size, align; // align is log2
};
struct Fat {
    unsigned n;
    Slice s[MAX_SLICES];
};

// Cheap test: FAT_MAGIC and a plausible slice count (Java class files share
// the magic but have a large "count").
bool is_fat(const byte *b, size_t n) noexcept;

// Parse and validate (bounds, alignment, no overlap). Throws CantPackException;
// FAT_MAGIC_64 is refused.
Fat parse(const byte *b, size_t n);

unsigned header_size(const Fat &f) noexcept;

// Assign new offsets for slices of the given sizes (same order, each aligned
// to its 2^align, first after the header). Updates f.s[i].offset/size.
void layout(Fat &f, const unsigned *sizes);

// Write header + slices (zero padding). data[i] holds f.s[i].size bytes.
void write(const Fat &f, const byte *const *data, MemBuffer &out);

// Remember the parts of a thin 64-bit Mach-O slice that `codesign` rewrites
// (header region and signature), plus a checksum of everything else.
void save_resign_info(const byte *slice, size_t n, MemBuffer &info);

// Rebuild the original slice from its current, possibly re-signed form.
// Returns false (out untouched) if the rest of the slice changed too.
bool undo_resign(const byte *cur, size_t n, const byte *info, size_t info_len, MemBuffer &out);

} // namespace upx_macho_fat

/* vim:set ts=4 sw=4 et: */
