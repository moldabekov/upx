/* macho_dyld_layout.h -- file layout of the macOS arm64 "macho/arm64-dyld" format

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.
 */

// Pure layout transform (no I/O). See
// docs/superpowers/specs/2026-11-07-macos-arm64-packing-design.md §4.1.
//
// A thin arm64 MH_EXECUTE is rewritten as
//   __PAGEZERO, __TEXT (header + head of __text), __UPXHOLE (zero-fill),
//   __UPXTEXT (rest of __TEXT), __DATA_CONST, __DATA, __UPXSTUB, __LINKEDIT
// The hole is every full page from __text up to the first __TEXT section
// that is read before initializers run (unwind info, ObjC/Swift metadata,
// DOF, Info.plist): code, stubs, __init_offsets, __const, __cstring, ...
// with every later file offset shifted, segment indices renumbered (chained
// fixups, or the opcode streams of LC_DYLD_INFO as emitted by Go), and the
// __unwind_info/__eh_frame section records kept in the
// head __TEXT command (dyld before dyld-1376 finds them by segment name).

#pragma once

namespace upx_macho_dyld {

constexpr upx_uint64_t PAGE = 16384;
constexpr unsigned MIN_HOLE_PAGES = 2;

// All fields little-endian 64-bit when stored in the packed file.
struct Plan {
    upx_uint64_t text_vmaddr;          // unslid vmaddr of __TEXT
    upx_uint64_t p0, p1;               // hole = [p0, p1), page aligned
    upx_uint64_t orig_filesize;        // signed input size
    upx_uint64_t hdr_region_size;      // file offset of the first __TEXT section
    upx_uint64_t sig_off, sig_size;    // LC_CODE_SIGNATURE of the input
    upx_uint64_t fixups_off, fixups_size; // chained fixups blob, or the dyld info opcode range
    upx_uint64_t linkedit_fileoff, linkedit_vmaddr;
    upx_uint64_t init_offsets_fileoff; // 0 = input has no __init_offsets
    upx_uint64_t init_offsets_size;    // bytes; copied after the stub entry in __UPXSTUB
    upx_uint64_t stub_size;            // set by the packer before build()
    upx_uint64_t fixups_kind;          // 0 = LC_DYLD_CHAINED_FIXUPS, 1 = LC_DYLD_INFO[_ONLY]
    upx_uint64_t code_size;            // leading bytes of the hole that are instructions
    upx_uint64_t hole_fileoff() const noexcept { return p0 - text_vmaddr; }
    upx_uint64_t hole_size() const noexcept { return p1 - p0; }
};
constexpr unsigned PLAN_WORDS = sizeof(Plan) / sizeof(upx_uint64_t);

// Validate a signed input and plan the split. Throws CantPackException.
Plan plan(const byte *in, size_t in_size);

// Bytes of load commands build() adds beyond the input's (for room checks).
unsigned extra_cmd_bytes(bool add_init_section) noexcept;

// Write the packed layout. `stub_seg` is the whole __UPXSTUB content
// (page multiple); `entry_off` is the initializer's offset inside it;
// `init_word_off` (4-aligned, room for 4 + init_offsets_size bytes) is where
// the new __init_offsets section goes: [stub entry, original entries...].
// The input's own __init_offsets record is dropped, so dyld runs the stub
// first and then the original initializers. Throws CantPackException.
void build(const byte *in, size_t in_size, const Plan &p, const byte *stub_seg,
           upx_uint64_t entry_off, upx_uint64_t init_word_off, MemBuffer &out);

// Inverse of build(): the signed input, byte for byte.
void restore(const byte *packed, size_t packed_size, const Plan &p, const byte *orig_hdr_region,
             const byte *orig_fixups, const byte *hole, const byte *sig, MemBuffer &out);

// Insert an empty seg_info_offset entry at each final segment index in
// `pos` (ascending). Returns the growth in bytes (blob padded to 8).
unsigned renumber_chained_fixups(const byte *blob, size_t size, const unsigned *pos, unsigned npos,
                                 MemBuffer &out);

// Serialize / deserialize a Plan (PLAN_WORDS little-endian u64).
void plan_store(const Plan &p, byte *dst) noexcept;
Plan plan_load(const byte *src) noexcept;

} // namespace upx_macho_dyld

/* vim:set ts=4 sw=4 et: */
