/*  arm64-darwin.macho-dyld-entry.S -- macOS arm64 "macho/arm64-dyld" initializer
*
*  This file is part of the UPX executable compressor.
*
*  Copyright (C) Markus Franz Xaver Johannes Oberhumer
*  All Rights Reserved.
*
*  UPX and the UCL library are free software; you can redistribute them
*  and/or modify them under the terms of the GNU General Public License as
*  published by the Free Software Foundation; either version 2 of
*  the License, or (at your option) any later version.
*/

// dyld calls this as the packed program's first initializer:
//      x0 argc, x1 argv, x2 envp, x3 apple, x4 ProgramVars *
// It passes those, the params block and the selected decompressor to the
// C restore code ("fold", appended by the packer right after MACHMAINZ),
// which restores the __text pages and chains to the original initializer.
// The packer links only the decompressor sections for its method.

#include "arch/arm64/v8/macros.S"

#define NO_METHOD_CHECK 1
// The decompressed bytes go to a file and are mapped fresh; no icache sync.
// (macOS also traps EL0 reads of CTR_EL0, which sync_cache does.)
#define NO_SYNC_CACHE 1

  section MACHMAINX
_start: .globl _start
        b upx_dyld_entry
        .balign 8
upx_dyld_params: .globl upx_dyld_params  // struct upx_dyld_params, filled by the packer
        .fill 11,8,0
upx_dyld_entry:
        stp x29,x30,[sp,#-16]!
        mov x29,sp
        adr x5,upx_dyld_params
        adr x6,f_decompress
        adr x7,fold_start
        blr x7  // upx_dyld_main(argc, argv, envp, apple, pvars, &params, f_decompress)
        ldp x29,x30,[sp],#16
        ret
f_decompress:

  section NRV_HEAD
        // empty

  section NRV2E
#include "arch/arm64/v8/nrv2e_d32.S"

  section NRV2D
#include "arch/arm64/v8/nrv2d_d32.S"

  section NRV2B
#include "arch/arm64/v8/nrv2b_d32.S"

  section NRV_TAIL
        // empty

// macOS reserves x18 (the kernel may clobber it), like Windows. Inside
// lzma_d.S, WINDOWS_BACK selects the -ffixed-x18 decoder (lzma_d_cf_win64.S)
// and a descending clear of the probability array; nothing else in this
// file depends on it. Scoped here so no other stub is affected.
#define WINDOWS_BACK 1
#include "arch/arm64/v8/lzma_d.S"
#undef WINDOWS_BACK

  section MACHMAINY
end_decompress: .globl end_decompress
        /* IDENTSTR goes here */

  section MACHMAINZ
        .balign 4
fold_start:  // the packer appends arm64-darwin.macho-dyld-fold here

/* vim:set ts=8 sw=8 et: */
