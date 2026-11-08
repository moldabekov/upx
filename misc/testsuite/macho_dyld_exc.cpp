/* macho_dyld_exc.cpp -- C++ test program: one static initializer, an
   exception thrown from code in the compressed range, caught in main().
   This file is part of the UPX executable compressor.
   Copyright (C) Markus Franz Xaver Johannes Oberhumer
 */
#include <cstdio>
#include "macho_dyld_fns.h"

static volatile uint32_t g_init = 0;
static struct Init {
    Init() { g_init = 42; }
} init_obj;

// thrower() is defined between the two halves so it lands mid-__text,
// inside the compressed range.
extern "C" {
MDF_M(MDF_DEF, 1)
}

extern "C" __attribute__((noinline)) uint32_t mdf_thrower(uint32_t x) {
    if (g_init == 42)
        throw (uint32_t) g_init; // only if the original initializer ran
    return x;
}

extern "C" {
MDF_M(MDF_DEF, 2)
}

int main(int argc, char **) {
    uint32_t a = (uint32_t) argc;
    try {
        MDF_M(MDF_CALL, 1)
        a = mdf_thrower(a);
        MDF_M(MDF_CALL, 2)
    } catch (uint32_t v) {
        std::printf("caught %u\n", (unsigned) v);
        return 7;
    }
    std::printf("no throw %08x\n", (unsigned) a);
    return 1;
}
