/* macho_dyld_large.c -- C test program with an 8 MiB executed function,
   so the compressed range spans many UPX blocks.
   This file is part of the UPX executable compressor.
   Copyright (C) Markus Franz Xaver Johannes Oberhumer
 */
#include <stdio.h>
#include "macho_dyld_fns.h"

MDF_ALL(MDF_DEF)

/* 2 Mi AArch64 NOPs (8 MiB) followed by ret; every byte is executed */
__attribute__((noinline, naked)) static void nop_sled(void) {
    __asm__ volatile(".fill 2097152, 4, 0xd503201f\n\tret");
}

int main(int argc, char **argv) {
    (void) argv;
    uint32_t a = (uint32_t) argc;
    MDF_M(MDF_CALL, 1)
    nop_sled();
    MDF_M(MDF_CALL, 2)
    printf("checksum %08x\n", a);
    return 0;
}
