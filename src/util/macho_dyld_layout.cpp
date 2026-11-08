/* macho_dyld_layout.cpp -- file layout of the macOS arm64 "macho/arm64-dyld" format

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
#include "macho_dyld_layout.h"

namespace upx_macho_dyld {
namespace {

constexpr unsigned LC_SEGMENT_64 = 0x19, LC_SYMTAB = 0x2, LC_DYSYMTAB = 0xb;
constexpr unsigned LC_CODE_SIGNATURE = 0x1d, LC_DYLD_CHAINED_FIXUPS = 0x80000034;
constexpr unsigned LC_DYLD_INFO = 0x22, LC_DYLD_INFO_ONLY = 0x80000022;
constexpr unsigned S_MOD_INIT_FUNC_POINTERS = 0x9, S_INIT_FUNC_OFFSETS = 0x16;
constexpr unsigned SEG_CMD = 72, SECT = 80, HDR = 32;
constexpr unsigned MAX_CMDS = 512, MAX_SEGS = 32;
constexpr unsigned PROT_RX = 5;
const char k_err[] = "macho/arm64-dyld: ";

// load commands whose only file offset is linkedit_data_command.dataoff
bool is_linkedit_data(unsigned c) noexcept {
    return c == 0x1e || c == 0x26 || c == 0x29 || c == 0x2b || c == 0x2e || c == 0x36 ||
           c == 0x80000033;
}
// load commands without file offsets
bool is_offsetless(unsigned c) noexcept {
    switch (c) {
    case 0xc:
    case 0xe:
    case 0x1b:
    case 0x20:
    case 0x24:
    case 0x27:
    case 0x2a:
    case 0x2d:
    case 0x32:
    case 0x80000018:
    case 0x8000001c:
    case 0x8000001f:
    case 0x80000023:
    case 0x80000028:
        return true;
    default:
        return false;
    }
}

upx_uint64_t page_up(upx_uint64_t x) noexcept { return (x + PAGE - 1) & ~(PAGE - 1); }

struct Cmd {
    unsigned cmd, size, off;
};

// Parsed, bounds-checked view of a thin arm64 Mach-O header.
struct Hdr {
    const byte *b = nullptr;
    size_t n = 0;
    unsigned ncmds = 0, sizeofcmds = 0;
    Cmd cmds[MAX_CMDS];
    unsigned seg_cmd[MAX_SEGS]; // index into cmds[] per segment ordinal
    unsigned nsegs = 0;
    int text = -1, linkedit = -1; // segment ordinals

    void need(size_t off, size_t len) const {
        if (off > n || len > n - off)
            throwCantPack("%struncated or corrupt file", k_err);
    }
    unsigned u32(size_t off) const {
        need(off, 4);
        return get_le32(b + off);
    }
    upx_uint64_t u64(size_t off) const {
        need(off, 8);
        return get_le64(b + off);
    }
    bool name_is(size_t off, const char *s) const {
        need(off, 16);
        return strncmp((const char *) b + off, s, 16) == 0;
    }
    const Cmd &seg(unsigned ordinal) const { return cmds[seg_cmd[ordinal]]; }
    unsigned nsects(const Cmd &c) const { return u32(c.off + 64); }
    size_t sect(const Cmd &c, unsigned i) const { return c.off + SEG_CMD + SECT * i; }
    const Cmd *find(unsigned cmd) const {
        for (unsigned i = 0; i < ncmds; i++)
            if (cmds[i].cmd == cmd)
                return &cmds[i];
        return nullptr;
    }
};

void parse(const byte *b, size_t n, Hdr &h) {
    h.b = b;
    h.n = n;
    if (h.u32(0) != 0xfeedfacf || h.u32(4) != 0x0100000c)
        throwCantPack("%snot a thin arm64 Mach-O", k_err);
    if ((h.u32(8) & 0x00ffffff) == 2) // CPU_SUBTYPE_ARM64E: pointer authentication
        throwCantPack("%sarm64e is not supported", k_err);
    if (h.u32(12) != 2)
        throwCantPack("%snot an executable", k_err);
    const unsigned flags = h.u32(24);
    if ((flags & 0x200000) == 0 || (flags & 0x4) == 0)
        throwCantPack("%sneeds MH_PIE and MH_DYLDLINK", k_err);
    h.ncmds = h.u32(16);
    h.sizeofcmds = h.u32(20);
    if (h.ncmds > MAX_CMDS)
        throwCantPack("%stoo many load commands", k_err);
    h.need(HDR, h.sizeofcmds);
    unsigned off = HDR;
    for (unsigned i = 0; i < h.ncmds; i++) {
        const unsigned c = h.u32(off), size = h.u32(off + 4);
        if (size < 8 || (size & 7) || size > HDR + h.sizeofcmds - off)
            throwCantPack("%sbad load command size", k_err);
        h.cmds[i] = Cmd{c, size, off};
        if (c == LC_SEGMENT_64) {
            if (size < SEG_CMD || h.nsegs >= MAX_SEGS)
                throwCantPack("%sbad segment command", k_err);
            if (size < SEG_CMD + SECT * (upx_uint64_t) h.u32(off + 64))
                throwCantPack("%ssegment sections exceed cmdsize", k_err);
            if (h.name_is(off + 8, "__TEXT"))
                h.text = (int) h.nsegs;
            if (h.name_is(off + 8, "__LINKEDIT"))
                h.linkedit = (int) h.nsegs;
            h.seg_cmd[h.nsegs++] = i;
        }
        off += size;
    }
    if (h.text < 0 || h.linkedit < 0 || h.linkedit != (int) h.nsegs - 1)
        throwCantPack("%sneeds __TEXT and a final __LINKEDIT segment", k_err);
    if (h.u64(h.seg(h.text).off + 40) != 0)
        throwCantPack("%s__TEXT must start at file offset 0", k_err);
}

void check_commands(const Hdr &h) {
    for (unsigned i = 0; i < h.ncmds; i++) {
        const unsigned c = h.cmds[i].cmd;
        if (c != LC_SEGMENT_64 && c != LC_SYMTAB && c != LC_DYSYMTAB && c != LC_CODE_SIGNATURE &&
            c != LC_DYLD_CHAINED_FIXUPS && c != LC_DYLD_INFO && c != LC_DYLD_INFO_ONLY &&
            !is_linkedit_data(c) && !is_offsetless(c))
            throwCantPack("%sunsupported load command 0x%x", k_err, c);
    }
    if (!h.find(LC_CODE_SIGNATURE))
        throwCantPack("%sinput must be signed (codesign -s - FILE)", k_err);
    const bool chained = h.find(LC_DYLD_CHAINED_FIXUPS) != nullptr;
    const bool info = h.find(LC_DYLD_INFO) != nullptr || h.find(LC_DYLD_INFO_ONLY) != nullptr;
    if (chained == info)
        throwCantPack(chained ? "%sboth chained fixups and LC_DYLD_INFO"
                              : "%sneeds chained fixups or LC_DYLD_INFO",
                      k_err);
}

// Scan all sections: refusals, __init_offsets, and the first __TEXT section offset.
void scan_sections(const Hdr &h, Plan &p) {
    p.hdr_region_size = h.n;
    for (unsigned s = 0; s < h.nsegs; s++) {
        const Cmd &c = h.seg(s);
        for (unsigned i = 0; i < h.nsects(c); i++) {
            const size_t so = h.sect(c, i);
            const unsigned type = h.u32(so + 64) & 0xff, foff = h.u32(so + 48);
            if (h.name_is(so, "__objc_nlclslist") || h.name_is(so, "__objc_nlcatlist"))
                throwCantPack("%sObjective-C +load is not supported", k_err);
            if (h.name_is(so, "__interpose"))
                throwCantPack("%sdyld interposing is not supported", k_err);
            if (type == S_MOD_INIT_FUNC_POINTERS)
                throwCantPack("%s__mod_init_func is not supported", k_err);
            if ((int) s == h.text && foff != 0 && foff < p.hdr_region_size)
                p.hdr_region_size = foff;
            if (type == S_INIT_FUNC_OFFSETS) {
                const upx_uint64_t size = h.u64(so + 40);
                if ((int) s != h.text || p.init_offsets_fileoff || size < 4 || (size & 3))
                    throwCantPack("%sunsupported __init_offsets", k_err);
                h.need(foff, size);
                p.init_offsets_fileoff = foff;
                p.init_offsets_size = size;
            }
        }
    }
}

// __TEXT sections that dyld, the Objective-C/Swift runtimes or other tools
// read before initializers run (or from the file on disk): they can't be in
// the hole. Unwind tables are read only when unwinding, after the stub ran.
bool is_load_time_section(const Hdr &h, size_t so) {
    h.need(so, 16);
    const char *n = (const char *) h.b + so;
    return h.name_is(so, "__info_plist") || strncmp(n, "__objc_", 7) == 0 ||
           strncmp(n, "__swift", 7) == 0 || strncmp(n, "__dof_", 6) == 0;
}

void plan_hole(const Hdr &h, Plan &p) {
    const Cmd &t = h.seg(h.text);
    p.text_vmaddr = h.u64(t.off + 24);
    bool have_text = false;
    for (unsigned i = 0; i < h.nsects(t); i++) {
        const size_t so = h.sect(t, i);
        if (h.name_is(so, "__text")) {
            p.p0 = page_up(h.u64(so + 32));
            have_text = true;
        }
    }
    if (!have_text)
        throwCantPack("%sno __TEXT,__text", k_err);
    // The hole is the zero-fill tail of the one __TEXT command, [p0, end of
    // __TEXT): every section record stays inside __TEXT, which both dyld-1286
    // (finds __unwind_info by the command name) and dyld-1323+ (refuses
    // records outside their command) need.
    const upx_uint64_t vmsize = h.u64(t.off + 32), filesize = h.u64(t.off + 48);
    if (filesize != vmsize || vmsize % PAGE != 0)
        throwCantPack("%s__TEXT is not file-backed up to its end", k_err);
    p.p1 = p.text_vmaddr + vmsize;
    for (unsigned i = 0; i < h.nsects(t); i++) {
        const size_t so = h.sect(t, i);
        const upx_uint64_t addr = h.u64(so + 32), size = h.u64(so + 40);
        if (!is_load_time_section(h, so) || addr + size <= p.p0)
            continue;
        throwCantPack("%s__TEXT,%.16s after the code is not supported", k_err,
                      (const char *) h.b + so);
    }
    if (p.p1 < p.p0 + MIN_HOLE_PAGES * PAGE)
        throwCantPack("%s__TEXT is too small", k_err);
    // instruction sections (__text, __stubs, ...) contiguous from p0: only
    // they get the branch filter; constants and tables after them do not
    upx_uint64_t code_end = p.p0;
    for (bool grew = true; grew;) {
        grew = false;
        for (unsigned i = 0; i < h.nsects(t); i++) {
            const size_t so = h.sect(t, i);
            const upx_uint64_t addr = h.u64(so + 32), size = h.u64(so + 40);
            const unsigned attrs = h.u32(so + 64) & 0xffffff00u;
            const bool code = (attrs & 0x80000000u) || (attrs & 0x400u); // PURE/SOME_INSTRUCTIONS
            if (code && addr <= code_end && addr + size > code_end) {
                code_end = addr + size;
                grew = true;
            }
        }
    }
    if (code_end > p.p1)
        code_end = p.p1;
    p.code_size = (code_end - p.p0) & ~(upx_uint64_t) 3;
}

// ---- LC_DYLD_INFO: rebase / bind opcode streams (<mach-o/loader.h>) ----

const Cmd *find_dyld_info(const Hdr &h) {
    const Cmd *c = h.find(LC_DYLD_INFO_ONLY);
    return c ? c : h.find(LC_DYLD_INFO);
}

// stream k: 0 rebase, 1 bind, 2 weak bind, 3 lazy bind (offset at 8 + 8*k)
constexpr unsigned DYLD_STREAMS = 4;

// New index of segment `old` once __UPXSTUB precedes __LINKEDIT.
unsigned new_seg_index(const Hdr &h, unsigned old) {
    if (old >= h.nsegs)
        throwCantPack("%sbad segment index in LC_DYLD_INFO", k_err);
    if ((int) old == h.text)
        throwCantPack("%sLC_DYLD_INFO fixups inside __TEXT are not supported", k_err);
    const unsigned n = old < (unsigned) h.linkedit ? old : old + 1;
    if (n > 15)
        throwCantPack("%stoo many segments for LC_DYLD_INFO", k_err);
    return n;
}

// Validate one opcode stream; if `out` (same length) is given, write the
// remapped SET_SEGMENT_AND_OFFSET opcodes there. Rebase and (weak) bind
// streams end at DONE like in dyld; the lazy stream has DONE between entries.
void walk_dyld_info(const Hdr &h, const byte *b, size_t n, unsigned k, byte *out) {
    const bool bind = k != 0, stop_at_done = k != 3;
    size_t i = 0;
    auto skip_leb = [&]() {
        while (i < n && (b[i] & 0x80))
            i++;
        if (i++ >= n)
            throwCantPack("%struncated LC_DYLD_INFO opcodes", k_err);
    };
    while (i < n) {
        const unsigned op = b[i] & 0xf0, imm = b[i] & 0x0f;
        const size_t at = i++;
        if (op == 0x00) { // DONE
            if (stop_at_done)
                return;
            continue;
        }
        if ((!bind && op == 0x20) || (bind && op == 0x70)) { // SET_SEGMENT_AND_OFFSET_ULEB
            const unsigned seg = new_seg_index(h, imm);
            if (out)
                out[at] = (byte) (op | seg);
            skip_leb();
            continue;
        }
        if (!bind) {
            switch (op) {
            case 0x10:
            case 0x40:
            case 0x50:
                break; // SET_TYPE, ADD_ADDR_IMM_SCALED, DO_IMM_TIMES
            case 0x30:
            case 0x60:
            case 0x70:
                skip_leb();
                break;
            case 0x80:
                skip_leb();
                skip_leb();
                break; // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
            default:
                throwCantPack("%sbad rebase opcode 0x%x", k_err, op);
            }
        } else {
            switch (op) {
            case 0x10:
            case 0x30:
            case 0x50:
            case 0x90:
            case 0xb0:
                break;
            case 0x20:
            case 0x60:
            case 0x80:
            case 0xa0:
                skip_leb();
                break;
            case 0xc0:
                skip_leb();
                skip_leb();
                break; // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
            case 0x40: // SET_SYMBOL_TRAILING_FLAGS_IMM: C string
                while (i < n && b[i])
                    i++;
                if (i++ >= n)
                    throwCantPack("%struncated LC_DYLD_INFO opcodes", k_err);
                break;
            default:
                throwCantPack("%sunsupported bind opcode 0x%x", k_err, op); // incl. THREADED
            }
        }
    }
}

void plan_dyld_info(const Hdr &h, Plan &p) {
    const Cmd *c = find_dyld_info(h);
    upx_uint64_t lo = ~0ull, hi = 0;
    for (unsigned k = 0; k < DYLD_STREAMS; k++) {
        const unsigned off = h.u32(c->off + 8 + 8 * k), size = h.u32(c->off + 12 + 8 * k);
        if (size == 0)
            continue;
        h.need(off, size);
        if (off < p.linkedit_fileoff || off + (upx_uint64_t) size > p.sig_off)
            throwCantPack("%sunexpected LC_DYLD_INFO layout", k_err);
        walk_dyld_info(h, h.b + off, size, k, nullptr);
        lo = off < lo ? off : lo;
        hi = off + (upx_uint64_t) size > hi ? off + (upx_uint64_t) size : hi;
    }
    const unsigned eoff = h.u32(c->off + 40), esize = h.u32(c->off + 44); // export trie
    if (esize && (eoff < p.linkedit_fileoff || eoff + (upx_uint64_t) esize > p.sig_off))
        throwCantPack("%sunexpected LC_DYLD_INFO layout", k_err);
    p.fixups_kind = 1;
    p.fixups_off = hi ? lo : p.linkedit_fileoff;
    p.fixups_size = hi ? hi - lo : 0;
}

void plan_linkedit(const Hdr &h, Plan &p) {
    const Cmd &l = h.seg(h.linkedit);
    p.linkedit_vmaddr = h.u64(l.off + 24);
    p.linkedit_fileoff = h.u64(l.off + 40);
    const Cmd *sig = h.find(LC_CODE_SIGNATURE), *fx = h.find(LC_DYLD_CHAINED_FIXUPS);
    p.sig_off = h.u32(sig->off + 8);
    p.sig_size = h.u32(sig->off + 12);
    h.need(p.sig_off, p.sig_size);
    if (!fx) {
        plan_dyld_info(h, p);
        return;
    }
    p.fixups_off = h.u32(fx->off + 8);
    p.fixups_size = h.u32(fx->off + 12);
    if (p.sig_off < p.linkedit_fileoff || p.fixups_off < p.linkedit_fileoff ||
        p.fixups_off + p.fixups_size > p.sig_off)
        throwCantPack("%sunexpected __LINKEDIT layout", k_err);
    // nothing but the signature may follow sig_off (it is dropped when packing)
    for (unsigned i = 0; i < h.ncmds; i++) {
        const Cmd &c = h.cmds[i];
        if (is_linkedit_data(c.cmd) &&
            h.u32(c.off + 8) + (upx_uint64_t) h.u32(c.off + 12) > p.sig_off)
            throwCantPack("%sdata after the code signature", k_err);
    }
}

// Copy a segment command with every file offset mapped through fo().
template <class FO>
void put_mapped_segment(const Hdr &h, const Cmd &c, FO fo, byte *dst) {
    memcpy(dst, h.b + c.off, c.size);
    if (get_le64(dst + 48) != 0)
        set_le64(dst + 40, fo(get_le64(dst + 40)));
    for (unsigned i = 0; i < get_le32(dst + 64); i++) {
        byte *s = dst + SEG_CMD + SECT * i;
        set_le32(s + 48, (unsigned) fo(get_le32(s + 48)));
    }
}

unsigned put_segment(byte *dst, const byte *proto, const char *name, upx_uint64_t vm,
                     upx_uint64_t vms, upx_uint64_t fo, upx_uint64_t fs, unsigned prot,
                     unsigned nsects) {
    memcpy(dst, proto, SEG_CMD);
    set_le32(dst + 4, SEG_CMD + SECT * nsects);
    memset(dst + 8, 0, 16);
    memcpy(dst + 8, name, strlen(name));
    set_le64(dst + 24, vm);
    set_le64(dst + 32, vms);
    set_le64(dst + 40, fo);
    set_le64(dst + 48, fs);
    set_le32(dst + 56, prot);
    set_le32(dst + 60, prot);
    set_le32(dst + 64, nsects);
    return SEG_CMD;
}

// The one __TEXT command at dst: file-backed [text_vmaddr, p0), zero-fill
// hole [p0, p1). Section records keep their addresses; those starting in
// the hole get file offset 0 (no file data). Returns bytes written.
template <class FO>
unsigned put_text(const Hdr &h, const Plan &p, FO fo, byte *dst, unsigned room) {
    const Cmd &t = h.seg(h.text);
    const unsigned n = h.nsects(t);
    if (SEG_CMD + SECT * (upx_uint64_t) n > room)
        throwCantPack("%sno room for load commands (relink with -Wl,-headerpad,0x1000)", k_err);
    byte *s = dst + SEG_CMD;
    unsigned ns = 0;
    for (unsigned i = 0; i < n; i++) {
        const size_t so = h.sect(t, i);
        if ((h.u32(so + 64) & 0xff) == S_INIT_FUNC_OFFSETS)
            continue; // moved into __UPXSTUB by build()
        byte *d = s + SECT * ns++;
        memcpy(d, h.b + so, SECT);
        set_le32(d + 48, h.u64(so + 32) >= p.p0 ? 0u : (unsigned) fo(h.u32(so + 48)));
    }
    put_segment(dst, h.b + t.off, "__TEXT", p.text_vmaddr, h.u64(t.off + 32), 0, p.hole_fileoff(),
                h.u32(t.off + 60), ns);
    set_le32(dst + 56, h.u32(t.off + 56)); // maxprot
    return SEG_CMD + SECT * ns;
}

// chained fixups: the segment entry inserted for __UPXSTUB
unsigned fixup_position(const Hdr &h) noexcept { return (unsigned) h.linkedit; }

unsigned fixups_growth(const Plan &p) noexcept {
    if (p.fixups_kind != 0) // dyld info opcodes are rewritten in place
        return 0;
    const upx_uint64_t fixups_size = p.fixups_size;
    const unsigned add = 4;
    return add + (unsigned) ((8 - (fixups_size + add) % 8) % 8);
}

} // namespace

unsigned extra_cmd_bytes(bool add_init_section) noexcept {
    // __UPXSTUB (+ its __init_offsets record when the input has none)
    return SEG_CMD + (add_init_section ? SECT : 0);
}

Plan plan(const byte *in, size_t in_size) {
    Hdr h;
    parse(in, in_size, h);
    check_commands(h);
    Plan p;
    memset(&p, 0, sizeof(p));
    p.orig_filesize = in_size;
    scan_sections(h, p);
    plan_hole(h, p);
    plan_linkedit(h, p);
    const upx_uint64_t need = HDR + h.sizeofcmds - 16 + extra_cmd_bytes(true);
    if (need > p.hdr_region_size)
        throwCantPack("%sno room for load commands (relink with -Wl,-headerpad,0x1000)", k_err);
    return p;
}

unsigned renumber_chained_fixups(const byte *blob, size_t size, const unsigned *pos, unsigned npos,
                                 MemBuffer &out) {
    if (size < 28)
        throwCantPack("%sbad chained fixups", k_err);
    const unsigned starts = get_le32(blob + 4);
    if (starts + 4 > size)
        throwCantPack("%sbad chained fixups", k_err);
    const unsigned seg_count = get_le32(blob + starts);
    if (seg_count > MAX_SEGS || starts + 4 + 4 * (size_t) seg_count > size)
        throwCantPack("%sbad chained fixups", k_err);
    const unsigned add = 4 * npos, total = seg_count + npos;
    const size_t len = size + add, padded = (len + 7) & ~(size_t) 7;
    out.alloc(padded);
    out.clear();
    byte *o = out;
    memcpy(o, blob, starts);
    set_le32(o + 8, get_le32(blob + 8) + add);   // imports_offset
    set_le32(o + 12, get_le32(blob + 12) + add); // symbols_offset
    set_le32(o + starts, total);
    unsigned src = 0, k = 0;
    for (unsigned i = 0; i < total; i++) {
        unsigned v = 0;
        if (k < npos && pos[k] == i) {
            k++;
        } else {
            v = get_le32(blob + starts + 4 + 4 * src++);
            if (v)
                v += add;
        }
        set_le32(o + starts + 4 + 4 * i, v);
    }
    const size_t tail = starts + 4 + 4 * (size_t) seg_count;
    memcpy(o + tail + add, blob + tail, size - tail);
    return (unsigned) (padded - size);
}

void build(const byte *in, size_t in_size, const Plan &p, const byte *stub_seg,
           upx_uint64_t entry_off, upx_uint64_t init_word_off, MemBuffer &out) {
    Hdr h;
    parse(in, in_size, h);
    MemBuffer fx;
    unsigned grow = 0;
    if (p.fixups_kind == 0) {
        const unsigned pos = fixup_position(h);
        grow = renumber_chained_fixups(in + p.fixups_off, (size_t) p.fixups_size, &pos, 1, fx);
    }
    const upx_uint64_t hole = p.hole_size(), hs = p.hole_fileoff(), he = hs + hole;
    const upx_uint64_t link = p.linkedit_fileoff, stub = p.stub_size, end = p.sig_off;
    const upx_uint64_t fx_end = p.fixups_off + p.fixups_size;
    const upx_uint64_t entry_vmoff = p.linkedit_vmaddr - p.text_vmaddr + entry_off;
    auto fo = [&](upx_uint64_t o) -> upx_uint64_t {
        if (o == 0 || o < hs)
            return o;
        if (o < he)
            throwCantPack("%sfile offset inside __text pages", k_err);
        if (o < link)
            return o - hole;
        return o - hole + stub + (o >= fx_end ? grow : 0);
    };

    const upx_uint64_t out_size = end - hole + stub + grow, stub_at = link - hole;
    out.alloc(out_size);
    out.clear();
    byte *o = out;
    memcpy(o, in, (size_t) hs);
    memcpy(o + hs, in + he, (size_t) (link - he));
    memcpy(o + stub_at, stub_seg, (size_t) stub);
    byte *lk = o + stub_at + stub;
    if (p.fixups_kind == 0) {
        memcpy(lk, in + link, (size_t) (p.fixups_off - link));
        memcpy(lk + (p.fixups_off - link), fx, fx.getSize());
        memcpy(lk + (p.fixups_off - link) + fx.getSize(), in + fx_end, (size_t) (end - fx_end));
    } else {
        memcpy(lk, in + link, (size_t) (end - link));
        const Cmd *di = find_dyld_info(h);
        for (unsigned k = 0; k < DYLD_STREAMS; k++) {
            const unsigned off = get_le32(in + di->off + 8 + 8 * k);
            const unsigned size = get_le32(in + di->off + 12 + 8 * k);
            if (size)
                walk_dyld_info(h, in + off, size, k, lk + (off - link));
        }
    }
    if (init_word_off == 0 || (init_word_off & 3) || init_word_off + 4 + p.init_offsets_size > stub)
        throwCantPack("%sno room for __init_offsets in __UPXSTUB", k_err);
    set_le32(o + stub_at + init_word_off, (unsigned) entry_vmoff);
    if (p.init_offsets_size)
        memcpy(o + stub_at + init_word_off + 4, in + p.init_offsets_fileoff,
               (size_t) p.init_offsets_size);

    // load commands
    const unsigned room = (unsigned) p.hdr_region_size - HDR;
    MemBuffer lcb(room);
    lcb.clear();
    byte *lc = lcb;
    unsigned w = 0, ncmds = 0;
    auto reserve = [&](unsigned bytes) {
        if (bytes > room - w)
            throwCantPack("%sno room for load commands (relink with -Wl,-headerpad,0x1000)", k_err);
    };
    for (unsigned i = 0; i < h.ncmds; i++) {
        const Cmd &c = h.cmds[i];
        if (c.cmd == LC_CODE_SIGNATURE)
            continue;
        if (c.cmd == LC_SEGMENT_64 && c.off == h.seg(h.text).off) {
            w += put_text(h, p, fo, lc + w, room - w);
            ncmds++;
            continue;
        }
        if (c.cmd == LC_SEGMENT_64 && c.off == h.seg(h.linkedit).off) {
            reserve(SEG_CMD + SECT + c.size);
            w += put_segment(lc + w, in + c.off, "__UPXSTUB", p.linkedit_vmaddr, stub, stub_at,
                             stub, PROT_RX, 1);
            {
                byte *s = lc + w;
                memcpy(s, "__init_offsets", 14);
                memcpy(s + 16, "__UPXSTUB", 9);
                set_le64(s + 32, p.linkedit_vmaddr + init_word_off);
                set_le64(s + 40, 4 + p.init_offsets_size);
                set_le32(s + 48, (unsigned) (stub_at + init_word_off));
                set_le32(s + 52, 2);
                set_le32(s + 64, S_INIT_FUNC_OFFSETS);
                w += SECT;
            }
            ncmds++;
            byte *d = lc + w;
            memcpy(d, in + c.off, c.size);
            const upx_uint64_t fs = end - link + grow;
            set_le64(d + 24, p.linkedit_vmaddr + stub);
            set_le64(d + 32, page_up(fs));
            set_le64(d + 40, fo(link));
            set_le64(d + 48, fs);
            w += c.size;
            ncmds++;
            continue;
        }
        reserve(c.size);
        byte *d = lc + w;
        if (c.cmd == LC_SEGMENT_64) {
            put_mapped_segment(h, c, fo, d);
        } else {
            memcpy(d, in + c.off, c.size);
            if (c.cmd == LC_DYLD_CHAINED_FIXUPS) {
                set_le32(d + 8, (unsigned) fo(p.fixups_off));
                set_le32(d + 12, (unsigned) fx.getSize());
            } else if (c.cmd == LC_DYLD_INFO || c.cmd == LC_DYLD_INFO_ONLY) {
                for (unsigned k = 8; k <= 40; k += 8) // rebase, bind, weak, lazy, export
                    if (get_le32(d + k + 4))
                        set_le32(d + k, (unsigned) fo(get_le32(d + k)));
            } else if (is_linkedit_data(c.cmd)) {
                set_le32(d + 8, (unsigned) fo(get_le32(d + 8)));
            } else if (c.cmd == LC_SYMTAB) {
                set_le32(d + 8, (unsigned) fo(get_le32(d + 8)));
                set_le32(d + 16, (unsigned) fo(get_le32(d + 16)));
            } else if (c.cmd == LC_DYSYMTAB) {
                for (unsigned k = 32; k <= 72; k += 8)
                    set_le32(d + k, (unsigned) fo(get_le32(d + k)));
            }
        }
        w += c.size;
        ncmds++;
    }
    set_le32(o + 16, ncmds);
    set_le32(o + 20, w);
    memcpy(o + HDR, lc, room);
}

// A Plan read from a packed file is untrusted: check every relation restore()
// relies on. All values are bounded by orig_filesize (<= 2 GiB), so the sums
// below cannot overflow.
static void check_plan(const Plan &p) {
    const upx_uint64_t lim = 0x80000000ull, n = p.orig_filesize;
    const bool ok = n > 0 && n < lim && p.stub_size < lim && p.stub_size % PAGE == 0 &&
                    p.fixups_kind <= 1 && p.text_vmaddr % PAGE == 0 && p.p0 % PAGE == 0 &&
                    p.p1 % PAGE == 0 && p.p0 >= p.text_vmaddr && p.p1 > p.p0 &&
                    p.p1 - p.text_vmaddr <= n && p.hdr_region_size <= p.hole_fileoff() &&
                    p.hole_fileoff() + p.hole_size() <= p.linkedit_fileoff &&
                    p.linkedit_fileoff <= p.fixups_off && p.fixups_size < lim &&
                    p.fixups_off + p.fixups_size <= p.sig_off && p.sig_size < lim &&
                    p.sig_off + p.sig_size <= n && p.code_size <= p.hole_size();
    if (!ok)
        throwCantUnpack("%sinconsistent packed file", k_err);
}

void restore(const byte *packed, size_t packed_size, const Plan &p, const byte *orig_hdr_region,
             const byte *orig_fixups, const byte *hole, const byte *sig, MemBuffer &out) {
    check_plan(p);
    const upx_uint64_t hs = p.hole_fileoff(), hl = p.hole_size(), he = hs + hl;
    const upx_uint64_t link = p.linkedit_fileoff, link_out = link - hl + p.stub_size;
    const upx_uint64_t fx_end = p.fixups_off + p.fixups_size;
    const unsigned grow = fixups_growth(p);
    const upx_uint64_t need = link_out + (p.sig_off - link) + grow;
    if (need > packed_size || p.sig_off + p.sig_size > p.orig_filesize || he > link ||
        p.hdr_region_size > hs)
        throwCantUnpack("%sinconsistent packed file", k_err);
    out.alloc(p.orig_filesize);
    out.clear();
    byte *o = out;
    memcpy(o, orig_hdr_region, (size_t) p.hdr_region_size);
    memcpy(o + p.hdr_region_size, packed + p.hdr_region_size, (size_t) (hs - p.hdr_region_size));
    memcpy(o + hs, hole, (size_t) hl);
    memcpy(o + he, packed + hs, (size_t) (link - he));
    const upx_uint64_t pre = p.fixups_off - link;
    memcpy(o + link, packed + link_out, (size_t) pre);
    memcpy(o + p.fixups_off, orig_fixups, (size_t) p.fixups_size);
    memcpy(o + fx_end, packed + link_out + pre + p.fixups_size + grow,
           (size_t) (p.sig_off - fx_end));
    memcpy(o + p.sig_off, sig, (size_t) p.sig_size);
}

void plan_store(const Plan &p, byte *dst) noexcept {
    const upx_uint64_t *f = &p.text_vmaddr;
    for (unsigned i = 0; i < PLAN_WORDS; i++)
        set_le64(dst + 8 * i, f[i]);
}

Plan plan_load(const byte *src) noexcept {
    Plan p;
    upx_uint64_t *f = &p.text_vmaddr;
    for (unsigned i = 0; i < PLAN_WORDS; i++)
        f[i] = get_le64(src + 8 * i);
    return p;
}

} // namespace upx_macho_dyld

/* vim:set ts=4 sw=4 et: */
