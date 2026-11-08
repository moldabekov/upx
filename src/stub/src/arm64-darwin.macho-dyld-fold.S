/*  arm64-darwin.macho-dyld-fold.S -- start of the "macho/arm64-dyld" restore code
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

// Linked flat (ld + objcopy -O binary) with arm64-darwin.macho-dyld-main.o.
// Offset 0 is the entry called by arm64-darwin.macho-dyld-entry.S.

#include "arch/arm64/v8/macros.S"

        .text
_start: .globl _start
        b upx_dyld_main

        .globl f_unfilter
#include "arch/arm64/v8/bxx.S"  // inline unfilter: FALLS THROUGH, so
        ret                       // return to the C caller here

/* vim:set ts=8 sw=8 et: */
