/* macho_dyld_fns.h -- generated-by-macro function chains for the
   macOS arm64 dyld-format tests (misc/cmake/macho_dyld_test.cmake).

   This file is part of the UPX executable compressor.
   Copyright (C) Markus Franz Xaver Johannes Oberhumer
 */
#pragma once
#include <stdint.h>

#define MDF_D(m, p) m(p##0) m(p##1) m(p##2) m(p##3) m(p##4) m(p##5) m(p##6) m(p##7) m(p##8) m(p##9)
#define MDF_C(m, p) MDF_D(m, p##0) MDF_D(m, p##1) MDF_D(m, p##2) MDF_D(m, p##3) MDF_D(m, p##4) \
                    MDF_D(m, p##5) MDF_D(m, p##6) MDF_D(m, p##7) MDF_D(m, p##8) MDF_D(m, p##9)
#define MDF_M(m, p) MDF_C(m, p##0) MDF_C(m, p##1) MDF_C(m, p##2) MDF_C(m, p##3) MDF_C(m, p##4) \
                    MDF_C(m, p##5) MDF_C(m, p##6) MDF_C(m, p##7) MDF_C(m, p##8) MDF_C(m, p##9)
/* 2000 functions f1000 .. f2999 */
#define MDF_ALL(m) MDF_M(m, 1) MDF_M(m, 2)

#define MDF_DEF(i) \
    __attribute__((noinline)) uint32_t f##i(uint32_t x) { \
        return (x * (2654435761u + i##u)) ^ (x >> ((i % 13) + 1)) ^ i##u; \
    }
#define MDF_CALL(i) a = f##i(a);
