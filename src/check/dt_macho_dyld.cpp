/* dt_macho_dyld.cpp -- doctests for util/macho_dyld_layout

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
#include "../util/macho_dyld_layout.h"

using namespace upx_macho_dyld;

namespace {

// A minimal signed-shaped arm64 MH_EXECUTE (nothing is executed):
//   __TEXT { __text, __init_offsets, __unwind_info }, __DATA_CONST, __DATA,
//   __LINKEDIT { chained fixups, symtab strings, 0x100-byte "signature" }
struct Variant {
    bool no_sig = false, dyld_info = false, interpose = false, objc_nl = false;
    bool mod_init = false, small_hole = false, cmd_note = false, no_init = false;
    bool no_room = false;
    // classic dyld info (LC_DYLD_INFO_ONLY) instead of chained fixups, as Go emits
    bool classic = false, classic_text = false;
    // __text ends after one page; a 2-page __TEXT,__const follows (hole extends over it)
    bool rodata = false;
    bool arm64e = false; // CPU_SUBTYPE_ARM64E
};

constexpr upx_uint64_t BASE = 0x100000000ull;
constexpr unsigned TEXT_END = 0x10100; // end of __text (file/vm offset)
constexpr unsigned LINK = 0x1c000, FX_SIZE = 0x38, STR = 0x1c040, SIG = 0x1c050, SIG_SIZE = 0x100;
constexpr unsigned FILE_SIZE = SIG + SIG_SIZE;
constexpr unsigned ORIG_INIT0 = 0x3f10;

struct Writer {
    MemBuffer &mb;
    unsigned pos = 32;
    void u32(unsigned off, unsigned v) { set_le32(mb + off, v); }
    void u64(unsigned off, upx_uint64_t v) { set_le64(mb + off, v); }
    void name16(unsigned off, const char *s) { strncpy((char *) (mb + off), s, 16); }
    unsigned seg(const char *n, upx_uint64_t vm, upx_uint64_t vms, unsigned fo, unsigned fs,
                 unsigned prot, unsigned nsects) {
        unsigned o = pos;
        u32(o, 0x19);
        u32(o + 4, 72 + 80 * nsects);
        name16(o + 8, n);
        u64(o + 24, vm);
        u64(o + 32, vms);
        u64(o + 40, fo);
        u64(o + 48, fs);
        u32(o + 56, prot);
        u32(o + 60, prot);
        u32(o + 64, nsects);
        pos += 72 + 80 * nsects;
        return o + 72;
    }
    void sect(unsigned at, const char *sn, upx_uint64_t addr, upx_uint64_t size, unsigned off,
              unsigned flags) {
        name16(at, sn);
        name16(at + 16, "__TEXT");
        u64(at + 32, addr);
        u64(at + 40, size);
        u32(at + 48, off);
        u32(at + 64, flags);
    }
    void cmd(unsigned c, unsigned size) {
        u32(pos, c);
        u32(pos + 4, size);
        pos += size;
    }
};

void make_test_macho(const Variant &v, MemBuffer &mb) {
    mb.dealloc();
    mb.alloc(FILE_SIZE);
    mb.clear();
    Writer w{mb};
    unsigned sizeofcmds = 72 + (72 + 3 * 80) + 72 + 72 + 72 + 16 + 24 + 80 + 32 + 24;
    if (v.rodata)
        sizeofcmds += 80;
    if (v.classic)
        sizeofcmds += 48 - 16; // LC_DYLD_INFO_ONLY replaces LC_DYLD_CHAINED_FIXUPS
    if (!v.no_sig)
        sizeofcmds += 16;
    if (v.dyld_info)
        sizeofcmds += 48;
    if (v.cmd_note)
        sizeofcmds += 40;
    const unsigned text_off = v.no_room ? ((32 + sizeofcmds + 64 + 3) & ~3u) : 0x3f00;
    const unsigned text_end = v.small_hole ? 0x8100 : TEXT_END;

    w.seg("__PAGEZERO", 0, BASE, 0, 0, 0, 0);
    unsigned s = w.seg("__TEXT", BASE, 0x14000, 0, 0x14000, 5, v.rodata ? 4 : 3);
    if (v.rodata) {
        w.sect(s, "__text", BASE + text_off, 0x8100 - text_off, text_off, 0x80000400);
        w.sect(s + 80, "__const", BASE + 0x8100, text_end - 0x8100, 0x8100, 0);
        s += 80;
    } else {
        w.sect(s, "__text", BASE + text_off, text_end - text_off, text_off, 0x80000400);
    }
    const char *init_name = v.no_init ? "__const" : "__init_offsets";
    unsigned init_flags = v.no_init ? 0 : (v.mod_init ? 0x9 : 0x16);
    w.sect(s + 80, init_name, BASE + text_end, 4, text_end, init_flags);
    const char *uw = v.interpose ? "__interpose" : (v.objc_nl ? "__objc_nlclslist" : "__unwind_info");
    w.sect(s + 160, uw, BASE + text_end + 4, 0x40, text_end + 4, 0);
    w.seg("__DATA_CONST", BASE + 0x14000, 0x4000, 0x14000, 0x4000, 3, 0);
    w.seg("__DATA", BASE + 0x18000, 0x4000, 0x18000, 0x4000, 3, 0);
    w.seg("__LINKEDIT", BASE + LINK, 0x4000, LINK, FILE_SIZE - LINK, 1, 0);
    if (v.classic) {
        w.u32(w.pos + 8, LINK);              // rebase_off
        w.u32(w.pos + 12, 8);                // rebase_size
        w.u32(w.pos + 16, LINK + 0x10);      // bind_off
        w.u32(w.pos + 20, 16);               // bind_size
        w.cmd(0x80000022, 48);               // LC_DYLD_INFO_ONLY
    } else {
        w.u32(w.pos + 8, LINK); // LC_DYLD_CHAINED_FIXUPS
        w.u32(w.pos + 12, FX_SIZE);
        w.cmd(0x80000034, 16);
    }
    w.u32(w.pos + 16, STR); // LC_SYMTAB: stroff, strsize
    w.u32(w.pos + 20, 8);
    w.cmd(0x2, 24);
    w.cmd(0xb, 80); // LC_DYSYMTAB, all zero
    w.u32(w.pos + 8, 12);
    strcpy((char *) (mb + w.pos + 12), "/usr/lib/dyld");
    w.cmd(0xe, 32); // LC_LOAD_DYLINKER
    w.u64(w.pos + 8, text_off);
    w.cmd(0x80000028, 24); // LC_MAIN
    if (v.dyld_info)
        w.cmd(0x80000022, 48);
    if (v.cmd_note)
        w.cmd(0x31, 40);
    if (!v.no_sig) {
        w.u32(w.pos + 8, SIG);
        w.u32(w.pos + 12, SIG_SIZE);
        w.cmd(0x1d, 16);
    }
    CHECK(w.pos == 32 + sizeofcmds);
    w.u32(0, 0xfeedfacf);
    w.u32(4, 0x0100000c); // CPU_TYPE_ARM64
    if (v.arm64e)
        w.u32(8, 0x80000002); // CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_PTRAUTH_ABI
    w.u32(12, 2);         // MH_EXECUTE
    unsigned ncmds = 10 + (v.no_sig ? 0 : 1) + (v.dyld_info ? 1 : 0) + (v.cmd_note ? 1 : 0);
    w.u32(16, ncmds);
    w.u32(20, sizeofcmds);
    w.u32(24, 0x00200085); // MH_PIE | MH_TWOLEVEL | MH_DYLDLINK | MH_NOUNDEFS
    for (unsigned i = text_off; i < text_end; i++)
        mb[i] = (byte) (i * 7 + 1);
    w.u32(text_end, ORIG_INIT0);
    if (v.classic) {
        // rebase: type pointer; segment 2 (__DATA_CONST) + 8; rebase once; done
        const byte rebase[8] = {0x11, (byte) (v.classic_text ? 0x21 : 0x22), 0x08, 0x51, 0, 0, 0, 0};
        // bind: ordinal 1, symbol "_x", type pointer, segment 3 (__DATA) + 0, bind, done
        const byte bind[16] = {0x11, 0x40, '_', 'x', 0, 0x51, 0x73, 0x00, 0x90, 0, 0, 0, 0, 0, 0, 0};
        memcpy(mb + LINK, rebase, sizeof(rebase));
        memcpy(mb + LINK + 0x10, bind, sizeof(bind));
    } else {
    // chained fixups: header, starts_in_image{seg_count 5, offsets}
    w.u32(LINK + 4, 0x20);       // starts_offset
    w.u32(LINK + 8, FX_SIZE);    // imports_offset
    w.u32(LINK + 12, FX_SIZE);   // symbols_offset
    w.u32(LINK + 20, 1);         // imports_format
    w.u32(LINK + 0x20, 5);       // seg_count
    w.u32(LINK + 0x20 + 12, 24); // __DATA_CONST
    w.u32(LINK + 0x20 + 16, 24); // __DATA
    }
    for (unsigned i = 0; i < SIG_SIZE; i++)
        mb[SIG + i] = 0xab;
}

// offset of the LC_SEGMENT_64 named `name`, or 0
unsigned find_seg(const byte *b, const char *name) {
    unsigned ncmds = get_le32(b + 16), off = 32;
    for (unsigned i = 0; i < ncmds; i++) {
        if (get_le32(b + off) == 0x19 && strncmp((const char *) b + off + 8, name, 16) == 0)
            return off;
        off += get_le32(b + off + 4);
    }
    return 0;
}

} // namespace

TEST_CASE("macho_dyld renumber fixups") {
    MemBuffer in, out;
    make_test_macho(Variant{}, in);
    const unsigned pos[3] = {2, 3, 6};
    unsigned grow = renumber_chained_fixups(in + LINK, FX_SIZE, pos, 3, out);
    CHECK(grow % 8 == 0);
    CHECK(out.getSize() == FX_SIZE + grow);
    const byte *s = out + 0x20;
    CHECK(get_le32(s) == 8);
    for (unsigned i : {2u, 3u, 6u})
        CHECK(get_le32(s + 4 + 4 * i) == 0);
    CHECK(get_le32(s + 4 + 4 * 4) == 24 + 12);
    CHECK(get_le32(s + 4 + 4 * 5) == 24 + 12);
    CHECK(get_le32(out + 8) == FX_SIZE + 12);
    CHECK(get_le32(out + 12) == FX_SIZE + 12);
}

TEST_CASE("macho_dyld plan") {
    MemBuffer in;
    make_test_macho(Variant{}, in);
    Plan p = plan(in, in.getSize());
    CHECK(p.text_vmaddr == BASE);
    CHECK(p.p0 == BASE + 0x4000);
    CHECK(p.p1 == BASE + 0x10000);
    CHECK(p.hole_size() == 0xc000);
    CHECK(p.code_size == 0xc000); // __text covers the whole hole
    CHECK(p.orig_filesize == FILE_SIZE);
    CHECK(p.hdr_region_size == 0x3f00);
    CHECK(p.sig_off == SIG);
    CHECK(p.sig_size == SIG_SIZE);
    CHECK(p.fixups_off == LINK);
    CHECK(p.fixups_size == FX_SIZE);
    CHECK(p.linkedit_fileoff == LINK);
    CHECK(p.linkedit_vmaddr == BASE + LINK);
    CHECK(p.init_offsets_fileoff == TEXT_END);
    CHECK(p.init_offsets_size == 4);
    Variant v;
    v.no_init = true;
    make_test_macho(v, in);
    CHECK(plan(in, in.getSize()).init_offsets_fileoff == 0);
}

TEST_CASE("macho_dyld plan refuses") {
    MemBuffer in;
    for (int k = 0; k < 8; k++) {
        Variant v;
        bool *flags[8] = {&v.no_sig,      &v.dyld_info, &v.interpose, &v.objc_nl,
                          &v.mod_init,    &v.small_hole, &v.cmd_note, &v.no_room};
        *flags[k] = true;
        make_test_macho(v, in);
        CAPTURE(k);
        CHECK_THROWS_AS(plan(in, in.getSize()), CantPackException);
    }
    make_test_macho(Variant{}, in);
    CHECK_THROWS_AS(plan(in, 100), CantPackException); // truncated
}

TEST_CASE("macho_dyld build") {
    MemBuffer in, out, stub(0x4000);
    make_test_macho(Variant{}, in);
    stub.fill(0, 0x4000, 0x5a);
    Plan p = plan(in, in.getSize());
    p.stub_size = 0x4000;
    build(in, in.getSize(), p, stub, 0x10, 0x3ff8, out);
    const byte *b = out;
    const char *order[] = {"__PAGEZERO", "__TEXT", "__UPXHOLE", "__UPXTEXT", "__DATA_CONST",
                           "__DATA", "__UPXSTUB", "__LINKEDIT"};
    unsigned prev = 0;
    for (const char *n : order) {
        unsigned o = find_seg(b, n);
        CAPTURE(n);
        CHECK(o > prev);
        prev = o;
    }
    unsigned hole = find_seg(b, "__UPXHOLE");
    CHECK(get_le64(b + hole + 48) == 0); // filesize
    CHECK(get_le64(b + hole + 24) == BASE + 0x4000);
    unsigned text = find_seg(b, "__TEXT");
    bool unwind_in_head = false;
    for (unsigned i = 0; i < get_le32(b + text + 64); i++) {
        const byte *sec = b + text + 72 + 80 * i;
        if (strncmp((const char *) sec, "__unwind_info", 16) == 0)
            unwind_in_head = get_le64(sec + 32) == BASE + TEXT_END + 4;
    }
    CHECK(unwind_in_head);
    unsigned link = find_seg(b, "__LINKEDIT");
    CHECK(get_le64(b + link + 24) == BASE + LINK + 0x4000);
    CHECK(find_seg(b, "__UPXSTUB") != 0);
    const unsigned grow = 16; // 3 entries = 12 bytes, padded to 8
    CHECK(out.getSize() == SIG - 0xc000 + 0x4000 + grow);
    // the original __init_offsets record is gone; __UPXSTUB has [stub entry, original entries]
    for (const char *sn : {"__TEXT", "__UPXTEXT"}) {
        unsigned so = find_seg(b, sn);
        for (unsigned i = 0; i < get_le32(b + so + 64); i++)
            CHECK(strncmp((const char *) b + so + 72 + 80 * i, "__init_offsets", 16) != 0);
    }
    unsigned st = find_seg(b, "__UPXSTUB");
    REQUIRE(get_le32(b + st + 64) == 1);
    const byte *is = b + st + 72;
    CHECK(strncmp((const char *) is, "__init_offsets", 16) == 0);
    CHECK(get_le64(is + 40) == 8);
    CHECK(get_le32(b + get_le32(is + 48)) == LINK + 0x10);
    CHECK(get_le32(b + get_le32(is + 48) + 4) == ORIG_INIT0);
    // the original entry itself is untouched
    CHECK(get_le32(b + TEXT_END - 0xc000) == ORIG_INIT0);
    // no LC_CODE_SIGNATURE left
    unsigned off = 32;
    for (unsigned i = 0; i < get_le32(b + 16); i++) {
        CHECK(get_le32(b + off) != 0x1d);
        off += get_le32(b + off + 4);
    }
}

TEST_CASE("macho_dyld build adds __init_offsets") {
    MemBuffer in, out, stub(0x4000);
    Variant v;
    v.no_init = true;
    make_test_macho(v, in);
    stub.clear();
    Plan p = plan(in, in.getSize());
    p.stub_size = 0x4000;
    build(in, in.getSize(), p, stub, 0x10, 0x3ffc, out);
    unsigned s = find_seg(out, "__UPXSTUB");
    REQUIRE(get_le32(out + s + 64) == 1);
    const byte *sec = out + s + 72;
    CHECK(strncmp((const char *) sec, "__init_offsets", 16) == 0);
    CHECK((get_le32(sec + 64) & 0xff) == 0x16);
    CHECK(get_le64(sec + 40) == 4);
    unsigned word_fileoff = get_le32(sec + 48);
    CHECK(get_le32(out + word_fileoff) == LINK + 0x10);
}

TEST_CASE("macho_dyld build+restore is exact") {
    for (int no_init = 0; no_init < 2; no_init++) {
        MemBuffer in, packed, back, stub(0x4000);
        Variant v;
        v.no_init = no_init != 0;
        make_test_macho(v, in);
        stub.clear();
        Plan p = plan(in, in.getSize());
        p.stub_size = 0x4000;
        build(in, in.getSize(), p, stub, 0x10, no_init ? 0x3ffc : 0x3ff8, packed);
        restore(packed, packed.getSize(), p, in, in + p.fixups_off, in + p.hole_fileoff(),
                in + p.sig_off, back);
        CAPTURE(no_init);
        REQUIRE(back.getSize() == in.getSize());
        CHECK(memcmp(back, in, in.getSize()) == 0);
    }
}

TEST_CASE("macho_dyld plan store/load") {
    MemBuffer in;
    make_test_macho(Variant{}, in);
    Plan p = plan(in, in.getSize());
    p.stub_size = 0x8000;
    byte buf[PLAN_WORDS * 8];
    plan_store(p, buf);
    Plan q = plan_load(buf);
    CHECK(memcmp(&p, &q, sizeof(p)) == 0);
}

/* vim:set ts=4 sw=4 et: */

TEST_CASE("macho_dyld restore rejects a corrupt plan") {
    MemBuffer in, packed, back, stub(0x4000);
    make_test_macho(Variant{}, in);
    stub.clear();
    const Plan good = [&] {
        Plan p = plan(in, in.getSize());
        p.stub_size = 0x4000;
        return p;
    }();
    build(in, in.getSize(), good, stub, 0x10, 0x3ff8, packed);
    auto bad = [&](void (*corrupt)(Plan &)) {
        Plan p = good;
        corrupt(p);
        return p;
    };
    void (*corruptions[])(Plan &) = {
        [](Plan &p) { p.fixups_off = p.linkedit_fileoff - 8; },  // fixups before LINKEDIT
        [](Plan &p) { p.fixups_size = p.sig_off; },              // fixups past signature
        [](Plan &p) { p.sig_off = p.linkedit_fileoff - 16; },    // signature before LINKEDIT
        [](Plan &p) { p.p1 = p.p0; },                            // empty hole
        [](Plan &p) { p.p0 += 1; },                              // unaligned hole
        [](Plan &p) { p.orig_filesize = ~0ull; },                // absurd size
        [](Plan &p) { p.hdr_region_size = p.hole_fileoff() + 16; },  // header overlaps hole
        [](Plan &p) { p.stub_size = ~0ull >> 1; },               // offsets overflow
    };
    for (unsigned k = 0; k < sizeof(corruptions) / sizeof(corruptions[0]); k++) {
        CAPTURE(k);
        const Plan p = bad(corruptions[k]);
        CHECK_THROWS_AS(restore(packed, packed.getSize(), p, in, in + good.fixups_off,
                                in + good.hole_fileoff(), in + good.sig_off, back),
                        CantPackException); // UPX's throwCantUnpack() throws CantPackException
        back.dealloc();
    }
}

TEST_CASE("macho_dyld classic dyld info (Go)") {
    MemBuffer in, packed, back, stub(0x4000);
    Variant v;
    v.classic = true;
    make_test_macho(v, in);
    stub.clear();
    Plan p = plan(in, in.getSize());
    CHECK(p.fixups_kind == 1);
    CHECK(p.fixups_off == LINK);
    CHECK(p.fixups_size == 0x20); // [rebase_off, bind_off + bind_size)
    p.stub_size = 0x4000;
    build(in, in.getSize(), p, stub, 0x10, 0x3ff8, packed);
    // segment indices remapped: __DATA_CONST 2 -> 4, __DATA 3 -> 5
    const unsigned lk = LINK - 0xc000 + 0x4000; // no fixups growth
    CHECK(packed[lk + 1] == 0x24);
    CHECK(packed[lk + 0x10 + 6] == 0x75);
    // LC_DYLD_INFO_ONLY offsets moved with __LINKEDIT
    unsigned off = 32;
    for (unsigned i = 0; i < get_le32(packed + 16); i++) {
        if (get_le32(packed + off) == 0x80000022) {
            CHECK(get_le32(packed + off + 8) == lk);
            CHECK(get_le32(packed + off + 16) == lk + 0x10);
        }
        off += get_le32(packed + off + 4);
    }
    CHECK(packed.getSize() == SIG - 0xc000 + 0x4000);
    restore(packed, packed.getSize(), p, in, in + p.fixups_off, in + p.hole_fileoff(),
            in + p.sig_off, back);
    REQUIRE(back.getSize() == in.getSize());
    CHECK(memcmp(back, in, in.getSize()) == 0);
}

TEST_CASE("macho_dyld classic dyld info refuses fixups in __TEXT") {
    MemBuffer in;
    Variant v;
    v.classic = v.classic_text = true;
    make_test_macho(v, in);
    CHECK_THROWS_AS(plan(in, in.getSize()), CantPackException);
}

TEST_CASE("macho_dyld hole extends over read-only __TEXT sections") {
    MemBuffer in, packed, back, stub(0x4000);
    Variant v;
    v.rodata = true;
    make_test_macho(v, in);
    stub.clear();
    Plan p = plan(in, in.getSize()); // __text alone has < 2 full pages
    CHECK(p.p0 == BASE + 0x4000);
    CHECK(p.p1 == BASE + 0x10000); // up to __init_offsets/__unwind_info, over __const
    CHECK(p.code_size == 0x8100 - 0x4000); // only __text gets the branch filter
    p.stub_size = 0x4000;
    build(in, in.getSize(), p, stub, 0x10, 0x3ff8, packed);
    // __const keeps only its tail [P1, end) as a record in __UPXTEXT
    unsigned t = find_seg(packed, "__UPXTEXT");
    bool found = false;
    for (unsigned i = 0; i < get_le32(packed + t + 64); i++) {
        const byte *sec = packed + t + 72 + 80 * i;
        if (strncmp((const char *) sec, "__const", 16) == 0) {
            found = true;
            CHECK(get_le64(sec + 32) == BASE + 0x10000);
            CHECK(get_le64(sec + 40) == 0x100);
        }
        CHECK(strncmp((const char *) sec, "__upxtail", 16) != 0); // __text ends in the hole
    }
    CHECK(found);
    restore(packed, packed.getSize(), p, in, in + p.fixups_off, in + p.hole_fileoff(),
            in + p.sig_off, back);
    REQUIRE(back.getSize() == in.getSize());
    CHECK(memcmp(back, in, in.getSize()) == 0);
}

TEST_CASE("macho_dyld refuses arm64e") {
    MemBuffer in;
    Variant v;
    v.arm64e = true;
    make_test_macho(v, in);
    CHECK_THROWS_AS(plan(in, in.getSize()), CantPackException);
}
