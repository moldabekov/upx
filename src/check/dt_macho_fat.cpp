/* dt_macho_fat.cpp -- doctests for util/macho_fat

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.
 */

#include "../conf.h"
#include "../util/membuffer.h"
#include "../util/macho_fat.h"

#if !defined(DOCTEST_CONFIG_DISABLE)

using namespace upx_macho_fat;

namespace {

// A minimal signed-shaped thin x86_64 slice: header + __TEXT{__text at 0x1000}
// + LC_CODE_SIGNATURE at the end. `body` fills the bytes after the header.
void make_slice(MemBuffer &mb, unsigned size, byte body, unsigned sig_size) {
    mb.dealloc();
    mb.alloc(size);
    mb.clear();
    byte *b = mb;
    set_le32(b, 0xfeedfacf);
    set_le32(b + 4, 0x01000007); // CPU_TYPE_X86_64
    set_le32(b + 12, 2);
    set_le32(b + 16, 2);
    set_le32(b + 20, 72 + 80 + 16);
    unsigned o = 32;
    set_le32(b + o, 0x19);
    set_le32(b + o + 4, 72 + 80);
    memcpy(b + o + 8, "__TEXT", 6);
    set_le32(b + o + 64, 1);
    memcpy(b + o + 72, "__text", 6);
    set_le32(b + o + 72 + 48, 0x1000);
    o += 72 + 80;
    set_le32(b + o, 0x1d);
    set_le32(b + o + 4, 16);
    set_le32(b + o + 8, size - sig_size);
    set_le32(b + o + 12, sig_size);
    for (unsigned i = 0x1000; i < size - sig_size; i++)
        b[i] = (byte) (body + i);
    for (unsigned i = size - sig_size; i < size; i++)
        b[i] = 0xcc;
}

void make_fat(MemBuffer &out, unsigned n) {
    Fat f{};
    f.n = n;
    MemBuffer s0, s1;
    make_slice(s0, 0x3000, 1, 0x100);
    make_slice(s1, 0x5000, 2, 0x200);
    f.s[0] = Slice{0x01000007, 3, 0, 0x3000, 12};
    f.s[1] = Slice{0x0100000c, 0, 0, 0x5000, 14};
    const unsigned sizes[2] = {0x3000, 0x5000};
    layout(f, sizes);
    const byte *data[2] = {s0, s1};
    write(f, data, out);
}

} // namespace

TEST_CASE("macho_fat parse/layout/write") {
    MemBuffer fat;
    make_fat(fat, 2);
    CHECK(is_fat(fat, fat.getSize()));
    Fat f = parse(fat, fat.getSize());
    CHECK(f.n == 2);
    CHECK(f.s[0].offset == 0x1000);
    CHECK(f.s[1].offset == 0x4000);
    CHECK(f.s[1].cputype == 0x0100000c);
    CHECK(fat.getSize() == 0x9000);
    CHECK(get_le32(fat + 0x4000) == 0xfeedfacf);
    // Java class file: same magic, large "count"
    byte cls[16] = {0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34};
    CHECK(!is_fat(cls, sizeof(cls)));
}

TEST_CASE("macho_fat parse refuses corrupt headers") {
    MemBuffer fat;
    make_fat(fat, 2);
    byte *b = fat;
    set_be32(b + 8 + 20 + 8, 0x2000); // slice 1 offset overlaps slice 0
    CHECK_THROWS_AS(parse(fat, fat.getSize()), CantPackException);
    make_fat(fat, 2);
    b = fat;
    set_be32(b + 8 + 12, 0x100000); // slice 0 size beyond file
    CHECK_THROWS_AS(parse(fat, fat.getSize()), CantPackException);
    make_fat(fat, 2);
    b = fat;
    set_be32(b, 0xcafebabf); // FAT_MAGIC_64
    CHECK_THROWS_AS(parse(fat, fat.getSize()), CantPackException);
}

TEST_CASE("macho_fat undo codesign on an unpacked slice") {
    MemBuffer orig, cur, info, back;
    make_slice(orig, 0x3000, 7, 0x100);
    save_resign_info(orig, orig.getSize(), info);
    // what codesign does: new signature size, header fields, file length
    make_slice(cur, 0x3000 - 0x100 + 0x180, 7, 0x180);
    REQUIRE(undo_resign(cur, cur.getSize(), info, info.getSize(), back));
    REQUIRE(back.getSize() == orig.getSize());
    CHECK(memcmp(back, orig, orig.getSize()) == 0);
    // body changed too: refuse to "restore"
    make_slice(cur, 0x3000, 8, 0x100);
    CHECK(!undo_resign(cur, cur.getSize(), info, info.getSize(), back));
}

#endif // DOCTEST_CONFIG_DISABLE

/* vim:set ts=4 sw=4 et: */
