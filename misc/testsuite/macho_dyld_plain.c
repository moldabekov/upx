/* macho_dyld_plain.c -- C test program without initializers.
   This file is part of the UPX executable compressor.
   Copyright (C) Markus Franz Xaver Johannes Oberhumer
 */
#include <stdio.h>
#include "macho_dyld_fns.h"

MDF_ALL(MDF_DEF)

int main(int argc, char **argv) {
    (void) argv;
    uint32_t a = (uint32_t) argc;
    MDF_ALL(MDF_CALL)
    printf("checksum %08x\n", a);
    return 0;
}
