/* macho_fat.cpp -- Mach-O universal ("fat") binaries for macho/arm64dyld

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.
 */

#include "../conf.h"
#include "membuffer.h"
#include "macho_fat.h"

namespace upx_macho_fat {
namespace {

constexpr unsigned FAT_MAGIC = 0xcafebabe, FAT_MAGIC_64 = 0xcafebabf;
constexpr unsigned ARCH = 20;                 // sizeof(fat_arch)
constexpr unsigned RESIGN_MAGIC = 0x52585055; // "UPXR"
constexpr unsigned RESIGN_HDR = 24;           // 6 x LE32
const char k_err[] = "macho/arm64dyld fat: ";

unsigned align_up(unsigned x, unsigned a) { return (x + a - 1) & ~(a - 1); }

// header region [0, first __TEXT section offset) and signature of a thin slice
void thin_parts(const byte *b, size_t n, unsigned &hdr_len, unsigned &sig_off, unsigned &sig_size) {
    if (n < 32 || get_le32(b) != 0xfeedfacf)
        throwCantPack("%sslice is not a 64-bit Mach-O", k_err);
    const unsigned ncmds = get_le32(b + 16), sizeofcmds = get_le32(b + 20);
    if (32 + (upx_uint64_t) sizeofcmds > n)
        throwCantPack("%sbad slice header", k_err);
    hdr_len = 32 + sizeofcmds;
    sig_off = (unsigned) n;
    sig_size = 0;
    unsigned off = 32, first_sect = 0;
    for (unsigned i = 0; i < ncmds; i++) {
        if (off + 8 > 32 + sizeofcmds)
            throwCantPack("%sbad slice load commands", k_err);
        const unsigned cmd = get_le32(b + off), size = get_le32(b + off + 4);
        if (size < 8 || off + size > 32 + sizeofcmds)
            throwCantPack("%sbad slice load commands", k_err);
        if (cmd == 0x19 && size >= 72 && strncmp((const char *) b + off + 8, "__TEXT", 16) == 0) {
            const unsigned ns = get_le32(b + off + 64);
            for (unsigned k = 0; k < ns && 72 + 80 * (upx_uint64_t) (k + 1) <= size; k++) {
                const unsigned so = get_le32(b + off + 72 + 80 * k + 48);
                if (so && (first_sect == 0 || so < first_sect))
                    first_sect = so;
            }
        }
        if (cmd == 0x1d && size >= 16) {
            sig_off = get_le32(b + off + 8);
            sig_size = get_le32(b + off + 12);
        }
        off += size;
    }
    if (first_sect > hdr_len && first_sect <= n)
        hdr_len = first_sect; // include the padding codesign may write into
    if (sig_off > n || sig_size > n - sig_off || sig_off < hdr_len)
        throwCantPack("%sbad slice signature", k_err);
}

} // namespace

bool is_fat(const byte *b, size_t n) noexcept {
    if (n < 8 || get_be32(b) != FAT_MAGIC)
        return false;
    const unsigned count = get_be32(b + 4);
    return count >= 1 && count <= MAX_SLICES;
}

unsigned header_size(const Fat &f) noexcept { return 8 + ARCH * f.n; }

Fat parse(const byte *b, size_t n) {
    if (n >= 4 && get_be32(b) == FAT_MAGIC_64)
        throwCantPack("%sFAT_MAGIC_64 is not supported", k_err);
    if (!is_fat(b, n))
        throwCantPack("%snot a universal binary", k_err);
    Fat f{};
    f.n = get_be32(b + 4);
    if (header_size(f) > n)
        throwCantPack("%struncated header", k_err);
    for (unsigned i = 0; i < f.n; i++) {
        const byte *a = b + 8 + ARCH * i;
        Slice &s = f.s[i];
        s = Slice{get_be32(a), get_be32(a + 4), get_be32(a + 8), get_be32(a + 12),
                  get_be32(a + 16)};
        if (s.align > 15 || (s.offset & ((1u << s.align) - 1)) || s.offset < header_size(f) ||
            s.size == 0 || s.offset > n || s.size > n - s.offset)
            throwCantPack("%sbad slice %u", k_err, i);
    }
    for (unsigned i = 0; i < f.n; i++)
        for (unsigned j = 0; j < f.n; j++)
            if (i != j && f.s[i].offset <= f.s[j].offset &&
                f.s[i].offset + f.s[i].size > f.s[j].offset)
                throwCantPack("%soverlapping slices", k_err);
    return f;
}

void layout(Fat &f, const unsigned *sizes) {
    unsigned order[MAX_SLICES];
    for (unsigned i = 0; i < f.n; i++)
        order[i] = i;
    for (unsigned i = 1; i < f.n; i++) // keep the original file order
        for (unsigned j = i; j > 0 && f.s[order[j]].offset < f.s[order[j - 1]].offset; j--) {
            const unsigned t = order[j];
            order[j] = order[j - 1];
            order[j - 1] = t;
        }
    unsigned cur = header_size(f);
    for (unsigned k = 0; k < f.n; k++) {
        Slice &s = f.s[order[k]];
        cur = align_up(cur, 1u << s.align);
        s.offset = cur;
        s.size = sizes[order[k]];
        cur += s.size;
    }
}

void write(const Fat &f, const byte *const *data, MemBuffer &out) {
    unsigned end = header_size(f);
    for (unsigned i = 0; i < f.n; i++)
        end = f.s[i].offset + f.s[i].size > end ? f.s[i].offset + f.s[i].size : end;
    out.dealloc();
    out.alloc(end);
    out.clear();
    byte *o = out;
    set_be32(o, FAT_MAGIC);
    set_be32(o + 4, f.n);
    for (unsigned i = 0; i < f.n; i++) {
        byte *a = o + 8 + ARCH * i;
        const Slice &s = f.s[i];
        set_be32(a, s.cputype);
        set_be32(a + 4, s.cpusubtype);
        set_be32(a + 8, s.offset);
        set_be32(a + 12, s.size);
        set_be32(a + 16, s.align);
        memcpy(o + s.offset, data[i], s.size);
    }
}

void save_resign_info(const byte *slice, size_t n, MemBuffer &info) {
    unsigned hdr_len, sig_off, sig_size;
    thin_parts(slice, n, hdr_len, sig_off, sig_size);
    info.dealloc();
    info.alloc(RESIGN_HDR + hdr_len + sig_size);
    byte *p = info;
    set_le32(p, RESIGN_MAGIC);
    set_le32(p + 4, hdr_len);
    set_le32(p + 8, sig_off);
    set_le32(p + 12, sig_size);
    set_le32(p + 16, (unsigned) n);
    set_le32(p + 20, upx_adler32(slice + hdr_len, sig_off - hdr_len));
    memcpy(p + RESIGN_HDR, slice, hdr_len);
    memcpy(p + RESIGN_HDR + hdr_len, slice + sig_off, sig_size);
}

bool undo_resign(const byte *cur, size_t n, const byte *info, size_t info_len, MemBuffer &out) {
    if (info_len < RESIGN_HDR || get_le32(info) != RESIGN_MAGIC)
        return false;
    const unsigned hdr_len = get_le32(info + 4), sig_off = get_le32(info + 8);
    const unsigned sig_size = get_le32(info + 12), size = get_le32(info + 16);
    if (info_len != RESIGN_HDR + (upx_uint64_t) hdr_len + sig_size || hdr_len > sig_off ||
        sig_off > size || sig_size > size - sig_off || sig_off > n)
        return false;
    if (upx_adler32(cur + hdr_len, sig_off - hdr_len) != get_le32(info + 20))
        return false;
    out.dealloc();
    out.alloc(size);
    out.clear();
    byte *o = out;
    memcpy(o, info + RESIGN_HDR, hdr_len);
    memcpy(o + hdr_len, cur + hdr_len, sig_off - hdr_len);
    memcpy(o + sig_off, info + RESIGN_HDR + hdr_len, sig_size);
    return true;
}

} // namespace upx_macho_fat

/* vim:set ts=4 sw=4 et: */
