/* arm64-darwin.macho-dyld-main.c -- restore code of the "macho/arm64-dyld" format

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.
 */

/* Runs inside the packed program's first initializer (see
   arm64-darwin.macho-dyld-entry.S). Decompresses the original __text pages
   and code signature into a sparse temp file, registers that signature with
   the kernel, maps the pages over the zero-fill hole, unlinks the file, and
   chains to the original first initializer.
   Spec: docs/superpowers/specs/2026-11-07-macos-arm64-packing-design.md §4.3

   Freestanding: raw Darwin syscalls (x16 = number, svc #0x80, carry set =
   error), no libSystem. Built with -mcmodel=tiny (PC-relative only). */

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned long size_t;

/* Darwin values (SDK <sys/fcntl.h>, <sys/mman.h>, <sys/errno.h>, <sys/syscall.h>) */
enum {
    O_RDWR = 0x2, O_CREAT = 0x200, O_EXCL = 0x800, O_NOFOLLOW = 0x100, O_CLOEXEC = 0x1000000,
    PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4,
    MAP_PRIVATE = 0x2, MAP_FIXED = 0x10, MAP_ANON = 0x1000,
    F_ADDFILESIGS_RETURN = 97,
    EIO = 5, EFAULT = 14, EINVAL = 22, ENAMETOOLONG = 63,
    NR_exit = 1, NR_write = 4, NR_open = 5, NR_close = 6, NR_unlink = 10, NR_munmap = 73,
    NR_fcntl = 92, NR_pwrite = 154, NR_mmap = 197, NR_ftruncate = 201, NR_getentropy = 500,
};

#define UPX_DYLD_MAGIC 0x31444C5944585055ull /* "UPXDYLD1" */
#define PATH_MAX_STUB 1024
#define NAME_HEX 16
#define EXIT_RESTORE_FAILED 127

struct upx_dyld_params {
    u64 magic, text_vmaddr, hole_vmoff, hole_len, orig_fileoff, orig_filesize,
        sig_off, sig_size, payload_vmoff, payload_len, orig_init0;
};
struct b_info { /* UPX block header, little-endian */
    u32 sz_unc, sz_cpr;
    u8 b_method, b_ftid, b_cto8, b_extra;
};
struct fsignatures { /* fsignatures_t */
    long long fs_file_start;
    void *fs_blob_start;
    size_t fs_blob_size;
    size_t fs_fsignatures_size;
    char fs_cdhash[20];
    int fs_hash_type;
};

typedef int f_expand(const u8 *, u32, u8 *, size_t *, unsigned);
typedef void f_init(int, char **, char **, char **, const void *);
extern void f_unfilter(u8 *, u32, unsigned cto8, unsigned ftid);

static long sys6(long n, long a, long b, long c, long d, long e, long f) {
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c,
                  x3 __asm__("x3") = d, x4 __asm__("x4") = e, x5 __asm__("x5") = f;
    register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80\n\tb.cc 1f\n\tneg x0, x0\n1:"
                     : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16)
                     : "memory", "cc");
    return x0; /* >= 0 success, < 0 is -errno */
}

/* gcc may emit calls to these even in freestanding mode */
void *memcpy(void *d, const void *s, size_t n) {
    u8 *dp = d;
    const u8 *sp = s;
    while (n--) *dp++ = *sp++;
    return d;
}
void *memset(void *d, int c, size_t n) {
    u8 *dp = d;
    while (n--) *dp++ = (u8) c;
    return d;
}

static size_t str_len(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void put(const char *s) { sys6(NR_write, 2, (long) s, (long) str_len(s), 0, 0, 0); }

static void __attribute__((noreturn)) fail(const char *step, long err) {
    char num[24];
    int i = (int) sizeof(num);
    unsigned long v = (unsigned long) (err < 0 ? -err : err);
    num[--i] = 0;
    do { num[--i] = (char) ('0' + v % 10); v /= 10; } while (v && i > 0);
    put("upx: "); put(step); put(" failed: errno "); put(&num[i]); put("\n");
    sys6(NR_exit, EXIT_RESTORE_FAILED, 0, 0, 0, 0, 0);
    for (;;) {}
}

static const char *find_tmpdir(char **envp) {
    for (; envp && *envp; envp++) {
        const char *e = *envp;
        if (e[0] == 'T' && e[1] == 'M' && e[2] == 'P' && e[3] == 'D' && e[4] == 'I' &&
            e[5] == 'R' && e[6] == '=')
            return e + 7;
    }
    return 0;
}

/* "<dir>/upx.<16 hex>"; returns 0, or -1 if it does not fit */
static int make_path(char *out, const char *dir, const u8 *rnd) {
    static const char hex[] = "0123456789abcdef";
    size_t n = str_len(dir), k = 0;
    if (n > 0 && dir[n - 1] == '/') n--;
    if (n + 5 + NAME_HEX + 1 > PATH_MAX_STUB) return -1;
    for (size_t i = 0; i < n; i++) out[k++] = dir[i];
    out[k++] = '/'; out[k++] = 'u'; out[k++] = 'p'; out[k++] = 'x'; out[k++] = '.';
    for (int i = 0; i < NAME_HEX / 2; i++) {
        out[k++] = hex[rnd[i] >> 4];
        out[k++] = hex[rnd[i] & 15];
    }
    out[k] = 0;
    return 0;
}

static long write_all(long fd, const u8 *p, u64 n, u64 off) {
    while (n) {
        long r = sys6(NR_pwrite, fd, (long) p, (long) n, (long) off, 0, 0);
        if (r <= 0) return r < 0 ? r : -EIO;
        p += r; n -= (u64) r; off += (u64) r;
    }
    return 0;
}

/* Decompress `n` bytes of b_info blocks from *src into dst; advances *src. */
static void unpack_blocks(const u8 **src, const u8 *src_end, u8 *dst, u64 n, f_expand *fexp) {
    while (n) {
        struct b_info h;
        if ((u64) (src_end - *src) < sizeof(h)) fail("decompress", EFAULT);
        memcpy(&h, *src, sizeof(h));
        *src += sizeof(h);
        if (h.sz_unc == 0 || h.sz_unc > n || h.sz_cpr > h.sz_unc ||
            (u64) (src_end - *src) < h.sz_cpr)
            fail("decompress", EFAULT);
        if (h.sz_cpr < h.sz_unc) {
            size_t out_len = h.sz_unc;
            int r = fexp(*src, h.sz_cpr, dst, &out_len, h.b_method);
            if (r != 0 || out_len != h.sz_unc) fail("decompress", EIO);
        } else {
            memcpy(dst, *src, h.sz_unc);
        }
        if (h.b_ftid) f_unfilter(dst, h.sz_unc, h.b_cto8, h.b_ftid);
        *src += h.sz_cpr;
        dst += h.sz_unc;
        n -= h.sz_unc;
    }
}

struct attempt { long err; const char *step; };

static long create_in(const char *dir, char *path, const struct upx_dyld_params *p,
                      const u8 *code, const u8 *sig, struct attempt *why) {
    u8 rnd[NAME_HEX / 2];
    long r = sys6(NR_getentropy, (long) rnd, sizeof(rnd), 0, 0, 0, 0);
    if (r < 0) { why->err = r; why->step = "open"; return -1; }
    if (make_path(path, dir, rnd) != 0) { why->err = ENAMETOOLONG; why->step = "path"; return -1; }
    long fd = sys6(NR_open, (long) path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600,
                   0, 0, 0);
    if (fd < 0) { why->err = fd; why->step = "open"; return -1; }
    if ((r = sys6(NR_ftruncate, fd, (long) p->orig_filesize, 0, 0, 0, 0)) < 0) {
        why->step = "ftruncate";
    } else if ((r = write_all(fd, code, p->hole_len, p->orig_fileoff)) < 0 ||
               (r = write_all(fd, sig, p->sig_size, p->sig_off)) < 0) {
        why->step = "pwrite";
    } else {
        return fd;
    }
    why->err = r;
    sys6(NR_unlink, (long) path, 0, 0, 0, 0, 0);
    sys6(NR_close, fd, 0, 0, 0, 0, 0);
    return -1;
}

void upx_dyld_main(int argc, char **argv, char **envp, char **apple, const void *pvars,
                   const struct upx_dyld_params *params, f_expand *fexp) {
    struct upx_dyld_params p;
    memcpy(&p, (const void *) params, sizeof(p));
    if (!pvars || p.magic != UPX_DYLD_MAGIC) fail("path", EINVAL);
    const u8 *mh = *(const u8 *const *) pvars;

    /* decompress code pages + signature into one anonymous buffer */
    u64 buf_len = p.hole_len + p.sig_size;
    long m = sys6(NR_mmap, 0, (long) buf_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (m < 0) fail("mmap", m);
    u8 *buf = (u8 *) m;
    const u8 *src = mh + p.payload_vmoff, *src_end = src + p.payload_len;
    unpack_blocks(&src, src_end, buf, p.hole_len, fexp);
    unpack_blocks(&src, src_end, buf + p.hole_len, p.sig_size, fexp);

    char path[PATH_MAX_STUB];
    struct attempt why = {EINVAL, "open"};
    const char *dirs[2] = {find_tmpdir(envp), "/tmp"};
    long fd = -1;
    for (int i = 0; i < 2 && fd < 0; i++)
        if (dirs[i]) fd = create_in(dirs[i], path, &p, buf, buf + p.hole_len, &why);
    if (fd < 0) fail(why.step, why.err);

    struct fsignatures fs;
    memset(&fs, 0, sizeof(fs));
    fs.fs_blob_start = (void *) p.sig_off;
    fs.fs_blob_size = p.sig_size;
    long r = sys6(NR_fcntl, fd, F_ADDFILESIGS_RETURN, (long) &fs, 0, 0, 0);
    if (r < 0) { sys6(NR_unlink, (long) path, 0, 0, 0, 0, 0); fail("addfilesigs", r); }
    u8 *hole = (u8 *) mh + p.hole_vmoff;
    m = sys6(NR_mmap, (long) hole, (long) p.hole_len, PROT_READ | PROT_EXEC, MAP_FIXED | MAP_PRIVATE,
             fd, (long) p.orig_fileoff);
    if (m != (long) hole) { sys6(NR_unlink, (long) path, 0, 0, 0, 0, 0); fail("mmap", m < 0 ? m : EFAULT); }
    sys6(NR_unlink, (long) path, 0, 0, 0, 0, 0);
    sys6(NR_close, fd, 0, 0, 0, 0, 0);
    sys6(NR_munmap, (long) buf, (long) buf_len, 0, 0, 0, 0);

    if (p.orig_init0) ((f_init *) (mh + p.orig_init0))(argc, argv, envp, apple, pvars);
}
