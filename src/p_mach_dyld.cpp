/* p_mach_dyld.cpp -- macOS arm64 "macho/arm64-dyld" format (macOS 13+)

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.
 */

#include "conf.h"
#include "file.h"
#include "filter.h"
#include "linker.h"
#include "packer.h"
#include "p_mach_dyld.h"
#include "util/macho_dyld_layout.h"
#include "util/macho_fat.h"
#include "util/membuffer.h"

#include "stub/arm64-darwin.macho-dyld-entry.h"
#include "stub/arm64-darwin.macho-dyld-fold.h"

using namespace upx_macho_dyld;

namespace {

constexpr upx_uint64_t PARAMS_MAGIC = 0x31444C5944585055ull;  // "UPXDYLD1"
constexpr upx_uint64_t TRAILER_MAGIC = 0x3152544459585055ull; // "UPXDYTR1"
constexpr unsigned B_INFO = 12;
constexpr unsigned PARAMS_WORDS = 11;
// trailer (all LE64): magic, Plan, pay_off, pay_len, meta_off, meta_u_adler,
// meta_c_adler, extra_len, code_len, data_u_adler, data_c_adler, reserved
constexpr unsigned TRAILER_EXTRA = 10;
constexpr unsigned TRAILER_SIZE = 8 * (1 + PLAN_WORDS + TRAILER_EXTRA);

unsigned up(unsigned x, unsigned a) { return (x + a - 1) & ~(a - 1); }

bool is_arm64_exec(const byte *h) {
    return get_le32(h) == 0xfeedfacf && get_le32(h + 4) == 0x0100000c && get_le32(h + 12) == 2;
}

void put_b_info(byte *b, unsigned unc, unsigned cpr, unsigned method, unsigned ftid, unsigned cto) {
    set_le32(b, unc);
    set_le32(b + 4, cpr);
    b[8] = (byte) method;
    b[9] = (byte) ftid;
    b[10] = (byte) cto;
    b[11] = 0;
}

// fileoff/filesize of the LC_SEGMENT_64 named `name`; false if absent
bool find_segment(const byte *b, size_t n, const char *name, unsigned &fo, unsigned &fs) {
    const unsigned ncmds = get_le32(b + 16), sizeofcmds = get_le32(b + 20);
    if (32 + (upx_uint64_t) sizeofcmds > n)
        return false;
    unsigned off = 32;
    for (unsigned i = 0; i < ncmds; i++) {
        if (off + 8 > 32 + sizeofcmds)
            return false;
        const unsigned cmd = get_le32(b + off), size = get_le32(b + off + 4);
        if (size < 8 || off + size > 32 + sizeofcmds)
            return false;
        if (cmd == 0x19 && size >= 72 && strncmp((const char *) b + off + 8, name, 16) == 0) {
            const upx_uint64_t f = get_le64(b + off + 40), s = get_le64(b + off + 48);
            if (f > n || s > n - f)
                return false;
            fo = (unsigned) f;
            fs = (unsigned) s;
            return true;
        }
        off += size;
    }
    return false;
}

// offset of the trailer inside the __UPXSTUB content, or -1
int find_trailer(const byte *seg, unsigned size) {
    for (unsigned o = 0; o + TRAILER_SIZE <= size; o += 8)
        if (get_le64(seg + o) == TRAILER_MAGIC)
            return (int) o;
    return -1;
}

// CodeDirectory flags & CS_RUNTIME (0x10000) in the embedded signature (big-endian blobs)
bool has_hardened_runtime(const byte *sig, upx_uint64_t size) {
    if (size < 12 || get_be32(sig) != 0xfade0cc0)
        return false;
    const unsigned count = get_be32(sig + 8);
    for (unsigned i = 0; i < count && 12 + 8 * (upx_uint64_t) i + 8 <= size; i++) {
        const unsigned off = get_be32(sig + 12 + 8 * i + 4);
        if (off + 16 <= size && get_be32(sig + off) == 0xfade0c02)
            return (get_be32(sig + off + 12) & 0x10000) != 0;
    }
    return false;
}

} // namespace

PackMachArm64Dyld::PackMachArm64Dyld(InputFile *f) : super(f) { bele = &N_BELE_RTP::le_policy; }

const int *PackMachArm64Dyld::getCompressionMethods(int method, int level) const {
    return Packer::getDefaultCompressionMethods_le32(method, level);
}

// Only 0x53: the stub's shared unfilter (stub/src/arch/arm64/v8/bxx.S) also
// rewrites the last word of the buffer, which the 0x52 filter (CT26ARM_LE in
// filter/ct.h) never filters; 0x53 (CTarm64) covers the last word too.
const int *PackMachArm64Dyld::getFilters() const {
    static const int filters[] = {0x53, FT_END};
    return filters;
}

Linker *PackMachArm64Dyld::newLinker() const { return new ElfLinkerArm64LE; }

void PackMachArm64Dyld::readWholeFile(MemBuffer &mb) {
    mb.alloc(file_size);
    fi->seek(0, SEEK_SET);
    fi->readx(mb, file_size_i32);
}

void PackMachArm64Dyld::buildLoader(const Filter *) {
    initLoader(0, stub_arm64_darwin_macho_dyld_entry, sizeof(stub_arm64_darwin_macho_dyld_entry));
    addLoader("MACHMAINX", nullptr);
    addLoader((M_IS_NRV2E(ph.method)   ? "NRV_HEAD,NRV2E,NRV_TAIL"
               : M_IS_NRV2D(ph.method) ? "NRV_HEAD,NRV2D,NRV_TAIL"
               : M_IS_NRV2B(ph.method) ? "NRV_HEAD,NRV2B,NRV_TAIL"
               : M_IS_LZMA(ph.method)  ? "LZMA_ELF00,LZMA_DEC20,LZMA_DEC30"
                                       : nullptr),
              nullptr);
    addLoader("MACHMAINY,IDENTSTR,+40,MACHMAINZ", nullptr);
    relocateLoader();
}

// ---- one thin arm64 slice (a whole file, or the arm64 slice of a fat file) ----

// Compress `len` bytes with the current method and no filter, without
// disturbing ph (which describes the main code block). Stores raw if that is
// not smaller. Returns the stored length.
unsigned PackMachArm64Dyld::compressPlain(const byte *src, unsigned len, MemBuffer &dst,
                                          unsigned &u_adler, unsigned &c_adler) {
    const PackHeader saved = ph;
    MemBuffer tmp(len);
    memcpy(tmp, src, len);
    dst.dealloc();
    dst.allocForCompression(len);
    ph.u_len = len;
    ph.filter = 0;
    ph.filter_cto = 0;
    ph.u_adler = ph.c_adler = upx_adler32(nullptr, 0);
    upx_compress_config_t cconf;
    cconf.reset();
    const bool ok = compress(tmp, len, dst, &cconf);
    unsigned c_len = ph.c_len;
    u_adler = ph.u_adler;
    c_adler = ph.c_adler;
    if (!ok || c_len >= len) {
        memcpy(dst, src, len);
        c_len = len;
        u_adler = c_adler = upx_adler32(src, len);
    }
    ph = saved;
    return c_len;
}

void PackMachArm64Dyld::decompressPlain(const byte *src, unsigned c_len, byte *dst, unsigned u_len,
                                        unsigned u_adler, unsigned c_adler) {
    if (c_len == u_len) { // stored
        memcpy(dst, src, u_len);
        if (upx_adler32(dst, u_len) != u_adler)
            throwChecksumError();
        return;
    }
    const PackHeader saved = ph;
    ph.u_len = u_len;
    ph.c_len = c_len;
    ph.u_adler = u_adler;
    ph.c_adler = c_adler;
    ph.saved_u_adler = ph.saved_c_adler = upx_adler32(nullptr, 0);
    ph.filter = 0;
    MemBuffer tmp(c_len);
    memcpy(tmp, src, c_len);
    try {
        decompress(tmp, dst);
    } catch (...) {
        ph = saved;
        throw;
    }
    ph = saved;
}

void PackMachArm64Dyld::packThin(const byte *in, size_t n, const byte *extra, unsigned extra_len,
                                 MemBuffer &out) {
    Plan p = plan(in, n);
    const unsigned hs = (unsigned) p.hole_fileoff(), hole = (unsigned) p.hole_size();
    const unsigned sig_size = (unsigned) p.sig_size;
    if (has_hardened_runtime(in + p.sig_off, p.sig_size))
        infoWarning("hardened runtime: the packed program needs "
                    "com.apple.security.cs.disable-library-validation");

    // hole = [code | data]: only the code block gets the branch filter (the
    // filter would rewrite constants that merely look like branches)
    const unsigned code_len = p.code_size ? (unsigned) p.code_size : hole;
    const unsigned data_len = hole - code_len;
    ibuf.dealloc();
    ibuf.alloc(code_len);
    memcpy(ibuf, in + hs, code_len);
    obuf.dealloc();
    obuf.allocForCompression(code_len);
    ph.u_len = code_len;
    Filter ft(ph.level);
    ft.addvalue = 0;
    upx_compress_config_t cconf;
    cconf.reset();
    compressWithFilters(&ft, 0, &cconf); // chooses the method for all blocks
    buildLoader(&ft);
    MemBuffer data_c, meta_c;
    unsigned data_ua = 0, data_ca = 0, meta_ua = 0, meta_ca = 0, data_clen = 0;
    if (data_len)
        data_clen = compressPlain(in + hs + code_len, data_len, data_c, data_ua, data_ca);
    // what only upx -d needs: header region | fixups | universal info
    const unsigned hdr_len = (unsigned) p.hdr_region_size, fx_len = (unsigned) p.fixups_size;
    const unsigned meta_len = hdr_len + fx_len + extra_len;
    MemBuffer meta(meta_len);
    memcpy(meta, in, hdr_len);
    memcpy(meta + hdr_len, in + p.fixups_off, fx_len);
    if (extra_len)
        memcpy(meta + hdr_len + fx_len, extra, extra_len);
    const unsigned meta_clen = compressPlain(meta, meta_len, meta_c, meta_ua, meta_ca);

    // __UPXSTUB: loader | fold | payload | meta | trailer | PackHeader | init words
    const unsigned lsize = getLoaderSize();
    if ((unsigned) getLoaderSectionStart("MACHMAINZ") != lsize)
        throwInternalError("macho/arm64dyld: MACHMAINZ must be last");
    const unsigned fold_size = sizeof(stub_arm64_darwin_macho_dyld_fold);
    const unsigned pay_off = up(lsize + fold_size, 8);
    const unsigned pay_len =
        B_INFO + ph.c_len + (data_len ? B_INFO + data_clen : 0) + B_INFO + sig_size;
    const unsigned meta_off = up(pay_off + pay_len, 8);
    const unsigned trl_off = up(meta_off + B_INFO + meta_clen, 8);
    const unsigned phs = ph.getPackHeaderSize();
    // new __init_offsets: [stub entry, original entries...]
    const unsigned init_word_off = up(trl_off + TRAILER_SIZE + phs, 4);
    const unsigned end = init_word_off + 4 + (unsigned) p.init_offsets_size;
    p.stub_size = up(end, (unsigned) PAGE);

    MemBuffer seg(p.stub_size);
    seg.clear();
    memcpy(seg, getLoader(), lsize);
    memcpy(seg + lsize, stub_arm64_darwin_macho_dyld_fold, fold_size);
    byte *w = seg + pay_off; // payload: code block, data block, signature (read by the stub)
    put_b_info(w, code_len, ph.c_len, ph.method, ph.filter, ph.filter_cto);
    memcpy(w + B_INFO, obuf, ph.c_len);
    w += B_INFO + ph.c_len;
    if (data_len) {
        put_b_info(w, data_len, data_clen, ph.method, 0, 0);
        memcpy(w + B_INFO, data_c, data_clen);
        w += B_INFO + data_clen;
    }
    put_b_info(w, sig_size, sig_size, ph.method, 0, 0); // stored
    memcpy(w + B_INFO, in + p.sig_off, sig_size);
    put_b_info(seg + meta_off, meta_len, meta_clen, ph.method, 0, 0);
    memcpy(seg + meta_off + B_INFO, meta_c, meta_clen);
    set_le64(seg + trl_off, TRAILER_MAGIC);
    plan_store(p, seg + trl_off + 8);
    const upx_uint64_t words[TRAILER_EXTRA] = {pay_off, pay_len, meta_off, meta_ua, meta_ca,
                                               extra_len, code_len, data_ua, data_ca, 0};
    for (unsigned i = 0; i < TRAILER_EXTRA; i++)
        set_le64(seg + trl_off + 8 + 8 * PLAN_WORDS + 8 * i, words[i]);
    byte *const php = seg + trl_off + TRAILER_SIZE;
    set_le32(php, UPX_MAGIC_LE32); // putPackHeader() patches a placeholder
    set_le32(php + 4, UPX_MAGIC2_LE32);
    ph.putPackHeader(SPAN_S_MAKE(byte, php, phs));

    // stub parameters (struct upx_dyld_params in arm64-darwin.macho-dyld-main.c)
    const upx_uint64_t stub_vmoff = p.linkedit_vmaddr - p.text_vmaddr;
    const upx_uint64_t params[PARAMS_WORDS] = {
        PARAMS_MAGIC, p.text_vmaddr, p.p0 - p.text_vmaddr, hole, hs, p.orig_filesize,
        p.sig_off,    p.sig_size,    stub_vmoff + pay_off,  pay_len,
        0 /* no chaining: dyld runs the original initializers after the stub */};
    const unsigned po = (unsigned) linker->getSymbolOffset("upx_dyld_params");
    for (unsigned i = 0; i < PARAMS_WORDS; i++)
        set_le64(seg + po + 8 * i, params[i]);

    build(in, n, p, seg, linker->getSymbolOffset("_start"), init_word_off, out);
}

// __UPXSTUB and its trailer in a packed thin slice; false if absent
static bool find_packed(const byte *in, size_t n, unsigned &so, unsigned &ss, int &t) {
    if (n < 32 || !is_arm64_exec(in) || !find_segment(in, n, "__UPXSTUB", so, ss))
        return false;
    t = find_trailer(in + so, ss);
    return t >= 0;
}

void PackMachArm64Dyld::unpackThin(const byte *in, size_t n, MemBuffer &out, MemBuffer &extra) {
    unsigned so = 0, ss = 0;
    int t = -1;
    if (!find_packed(in, n, so, ss, t))
        throwCantUnpack("macho/arm64dyld: __UPXSTUB trailer not found");
    const byte *seg = in + so;
    const byte *trl = seg + t;
    const Plan p = plan_load(trl + 8);
    upx_uint64_t w[TRAILER_EXTRA];
    for (unsigned i = 0; i < TRAILER_EXTRA; i++)
        w[i] = get_le64(trl + 8 + 8 * PLAN_WORDS + 8 * i);
    const upx_uint64_t pay_off = w[0], pay_len = w[1], meta_off = w[2], ex_len = w[5];
    const upx_uint64_t code_len = w[6], hole = p.hole_size(), data_len = hole - code_len;
    const upx_uint64_t meta_len = p.hdr_region_size + p.fixups_size + ex_len;
    auto fail = [] { throwCantUnpack("macho/arm64dyld: corrupt packed data"); };
    if (pay_off > ss || pay_len > ss - pay_off || meta_off > ss || ss - meta_off < B_INFO ||
        code_len != ph.u_len || code_len > hole || meta_len > (upx_uint64_t) 1 << 31)
        fail();
    // payload: code block (ph), data block, signature
    const byte *b = seg + pay_off, *pend = b + pay_len;
    auto block = [&](upx_uint64_t want, unsigned &clen) {
        if (pend - b < (ptrdiff_t) B_INFO || get_le32(b) != want)
            fail();
        clen = get_le32(b + 4);
        if (clen > want || (upx_uint64_t) (pend - b - B_INFO) < clen)
            fail();
        const byte *data = b + B_INFO;
        b += B_INFO + clen;
        return data;
    };
    unsigned c = 0;
    MemBuffer hole_buf(hole);
    const byte *code = block(code_len, c);
    if (c != ph.c_len)
        fail();
    ibuf.dealloc();
    ibuf.alloc(ph.c_len);
    memcpy(ibuf, code, ph.c_len);
    decompress(ibuf, hole_buf); // verifies the checksums of the *filtered* data
    if (ph.filter) {
        Filter ft(ph.level);
        ft.init(ph.filter, 0);
        ft.cto = (byte) ph.filter_cto;
        ft.unfilter(hole_buf, (unsigned) code_len);
    }
    if (data_len) {
        const byte *data = block(data_len, c);
        decompressPlain(data, c, hole_buf + code_len, (unsigned) data_len, (unsigned) w[7],
                        (unsigned) w[8]);
    }
    const byte *sig = block(p.sig_size, c);
    if (c != p.sig_size)
        fail();
    // what only upx -d needs
    const byte *mb = seg + meta_off;
    const unsigned mclen = get_le32(mb + 4);
    if (get_le32(mb) != meta_len || mclen > meta_len || ss - meta_off - B_INFO < mclen)
        fail();
    MemBuffer meta(meta_len ? meta_len : 1);
    decompressPlain(mb + B_INFO, mclen, meta, (unsigned) meta_len, (unsigned) w[3], (unsigned) w[4]);
    restore(in, n, p, meta, meta + p.hdr_region_size, hole_buf, sig, out);
    extra.dealloc();
    if (ex_len) {
        extra.alloc(ex_len);
        memcpy(extra, meta + p.hdr_region_size + p.fixups_size, (size_t) ex_len);
    }
}

// ---- universal binaries: pack the arm64 slice, keep the others ----

// index of the single plain-arm64 slice; -1 if none. Throws for arm64e or
// several arm64 slices.
static int arm64_slice(const upx_macho_fat::Fat &f) {
    int arm = -1;
    for (unsigned i = 0; i < f.n; i++) {
        if (f.s[i].cputype != 0x0100000c)
            continue;
        if ((f.s[i].cpusubtype & 0x00ffffff) == 2)
            throwCantPack("macho/arm64dyld: universal binaries with arm64e slices are not supported");
        if (arm >= 0)
            throwCantPack("macho/arm64dyld: more than one arm64 slice");
        arm = (int) i;
    }
    return arm;
}

static void check_gate() {
    if (!opt->darwin_macho.force_macos && !is_envvar_true("UPX_DEBUG_FORCE_PACK_MACOS"))
        throwCantPack("macOS is currently not supported (try --force-macos)");
}

tribool PackMachArm64Dyld::canPack() {
    byte hdr[32];
    if (file_size < 4096)
        return false;
    fi->seek(0, SEEK_SET);
    fi->readx(hdr, sizeof(hdr));
    const bool fat = upx_macho_fat::is_fat(hdr, sizeof(hdr));
    if (!fat && !is_arm64_exec(hdr))
        return false;
    MemBuffer in;
    readWholeFile(in);
    const byte *slice = in;
    size_t n = file_size_u;
    if (fat) {
        const upx_macho_fat::Fat f = upx_macho_fat::parse(in, file_size_u);
        const int arm = arm64_slice(f);
        if (arm < 0)
            return false; // no arm64: leave it to the other Mach-O packers
        slice = in + f.s[arm].offset;
        n = f.s[arm].size;
    }
    check_gate();
    // Not checkAlreadyPacked(): it scans the whole file for "UPX!", and
    // binaries that embed UPX stubs (e.g. upx itself) contain that magic.
    unsigned so = 0, ss = 0;
    if (find_segment(slice, n, "__UPXSTUB", so, ss))
        throwAlreadyPacked();
    (void) plan(slice, n); // throws CantPackException with the reason
    return true;
}

void PackMachArm64Dyld::pack(OutputFile *fo) {
    MemBuffer in, out;
    readWholeFile(in);
    ph.u_file_size = file_size;
    if (!upx_macho_fat::is_fat(in, file_size_u)) {
        packThin(in, file_size_u, nullptr, 0, out);
    } else {
        using namespace upx_macho_fat;
        const Fat f = parse(in, file_size_u);
        const int arm = arm64_slice(f);
        // extra: "UPXF", n, n x {cputype, cpusubtype, offset, size, align},
        //        then per other slice: index, length, resign info (or length 0)
        MemBuffer ex(8 + 20 * f.n + f.n * 8 + file_size_u), info;
        ex.clear();
        byte *e = ex;
        unsigned el = 0;
        auto put = [&](unsigned v) { set_le32(e + el, v); el += 4; };
        put(0x46585055);
        put(f.n);
        for (unsigned i = 0; i < f.n; i++) {
            put(f.s[i].cputype); put(f.s[i].cpusubtype); put(f.s[i].offset);
            put(f.s[i].size); put(f.s[i].align);
        }
        for (unsigned i = 0; i < f.n; i++) {
            if ((int) i == arm)
                continue;
            const byte *sl = in + f.s[i].offset;
            const bool thin64 = f.s[i].size >= 32 && get_le32(sl) == 0xfeedfacf;
            if (thin64)
                save_resign_info(sl, f.s[i].size, info);
            put(i);
            put(thin64 ? info.getSize() : 0);
            if (thin64) {
                memcpy(e + el, info, info.getSize());
                el += info.getSize();
            }
        }
        MemBuffer packed;
        packThin(in + f.s[arm].offset, f.s[arm].size, ex, el, packed);
        Fat nf = f;
        unsigned sizes[MAX_SLICES];
        const byte *data[MAX_SLICES];
        for (unsigned i = 0; i < f.n; i++) {
            sizes[i] = (int) i == arm ? packed.getSize() : f.s[i].size;
            data[i] = (int) i == arm ? (const byte *) packed : in + f.s[i].offset;
        }
        layout(nf, sizes);
        write(nf, data, out);
    }
    if (out.getSize() >= file_size_u)
        throwNotCompressible();
    fo->write(out, out.getSize());
}

tribool PackMachArm64Dyld::canUnpack() {
    byte hdr[32];
    if (file_size < 4096)
        return false;
    fi->seek(0, SEEK_SET);
    fi->readx(hdr, sizeof(hdr));
    const bool fat = upx_macho_fat::is_fat(hdr, sizeof(hdr));
    if (!fat && !is_arm64_exec(hdr))
        return false;
    MemBuffer in;
    readWholeFile(in);
    const byte *slice = in;
    size_t n = file_size_u;
    if (fat) {
        upx_macho_fat::Fat f;
        int arm = -1;
        try {
            f = upx_macho_fat::parse(in, file_size_u);
            arm = arm64_slice(f);
        } catch (const CantPackException &) {
            return false;
        }
        if (arm < 0)
            return false;
        slice = in + f.s[arm].offset;
        n = f.s[arm].size;
    }
    unsigned so = 0, ss = 0;
    int t = -1;
    if (!find_packed(slice, n, so, ss, t)) {
        // A dyld-linked (MH_DYLDLINK) executable without __UPXSTUB is not packed
        // by any UPX format (the old macho/arm64 output is static), so answer
        // "not packed" here instead of letting the old Mach-O code guess.
        return (n >= 32 && is_arm64_exec(slice) && (get_le32(slice + 24) & 0x4)) ? tribool(-1)
                                                                              : tribool(false);
    }
    const unsigned at = so + (unsigned) t + TRAILER_SIZE;
    return getPackHeader(slice + at, (int) (so + ss - at)) ? tribool(true) : tribool(-1);
}

void PackMachArm64Dyld::unpack(OutputFile *fo) {
    MemBuffer in, out;
    readWholeFile(in);
    if (!upx_macho_fat::is_fat(in, file_size_u)) {
        MemBuffer unused;
        unpackThin(in, file_size_u, out, unused);
        if (out.getSize() != ph.u_file_size)
            throwCantUnpack("macho/arm64dyld: size mismatch");
    } else {
        using namespace upx_macho_fat;
        const Fat f = parse(in, file_size_u);
        const int arm = arm64_slice(f);
        if (arm < 0)
            throwCantUnpack("macho/arm64dyld: no arm64 slice");
        MemBuffer slice, ex;
        unpackThin(in + f.s[arm].offset, f.s[arm].size, slice, ex);
        // original layout from the extra blob
        const byte *e = ex;
        const size_t el = ex.getSize();
        if (el < 8 || get_le32(e) != 0x46585055 || get_le32(e + 4) != f.n ||
            8 + 20 * (size_t) f.n > el)
            throwCantUnpack("macho/arm64dyld: corrupt universal info");
        Fat of{};
        of.n = f.n;
        for (unsigned i = 0; i < f.n; i++) {
            const byte *a = e + 8 + 20 * i;
            of.s[i] = Slice{get_le32(a), get_le32(a + 4), get_le32(a + 8), get_le32(a + 12),
                            get_le32(a + 16)};
        }
        MemBuffer restored[MAX_SLICES];
        const byte *data[MAX_SLICES];
        unsigned sizes[MAX_SLICES];
        bool exact = slice.getSize() == of.s[arm].size;
        size_t pos = 8 + 20 * (size_t) f.n;
        for (unsigned i = 0; i < f.n; i++) {
            data[i] = (int) i == arm ? (const byte *) slice : in + f.s[i].offset;
            sizes[i] = (int) i == arm ? slice.getSize() : f.s[i].size;
        }
        while (pos + 8 <= el) {
            const unsigned i = get_le32(e + pos), len = get_le32(e + pos + 4);
            pos += 8;
            if (i >= f.n || (int) i == arm || len > el - pos)
                throwCantUnpack("macho/arm64dyld: corrupt universal info");
            if (len && undo_resign(in + f.s[i].offset, f.s[i].size, e + pos, len, restored[i])) {
                data[i] = restored[i];
                sizes[i] = restored[i].getSize();
            }
            exact = exact && sizes[i] == of.s[i].size;
            pos += len;
        }
        Fat nf = of;
        if (!exact) { // a slice changed beyond re-signing: fresh layout
            nf = f;
            layout(nf, sizes);
        }
        write(nf, data, out);
        if (exact && out.getSize() != ph.u_file_size)
            throwCantUnpack("macho/arm64dyld: size mismatch");
    }
    if (fo)
        fo->write(out, out.getSize());
}

/* vim:set ts=4 sw=4 et: */
