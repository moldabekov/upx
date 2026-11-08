/* p_mach_dyld.h -- macOS arm64 "macho/arm64-dyld" format (macOS 13+)

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.
 */

#pragma once

// Packs a thin arm64 MH_EXECUTE so that dyld still loads it: the full pages
// of __TEXT,__text are cut out of the file and stored compressed in a new
// __UPXSTUB segment; a stub run as the first initializer restores them from
// a sparse temp file covered by the original code signature.
// The user signs the packed file (codesign -s - FILE) after packing.
// See docs/superpowers/specs/2026-11-07-macos-arm64-packing-design.md

class PackMachArm64Dyld final : public Packer {
    typedef Packer super;

public:
    explicit PackMachArm64Dyld(InputFile *f);
    virtual int getVersion() const override { return 14; }
    virtual int getFormat() const override { return UPX_F_MACH_ARM64_DYLD; }
    virtual const char *getName() const override { return "macho/arm64dyld"; } // <= 15 chars (ui.cpp)
    virtual const char *getFullName(const Options *) const override {
        return "arm64-darwin.macho-dyld";
    }
    virtual const int *getCompressionMethods(int method, int level) const override;
    virtual const int *getFilters() const override;

    virtual tribool canPack() override;
    virtual void pack(OutputFile *fo) override;
    virtual tribool canUnpack() override;
    virtual void unpack(OutputFile *fo) override;

protected:
    virtual void buildLoader(const Filter *ft) override;
    virtual Linker *newLinker() const override;

private:
    void readWholeFile(MemBuffer &mb);
    // one thin arm64 slice; `extra` is stored in the trailer (universal info)
    void packThin(const byte *in, size_t n, const byte *extra, unsigned extra_len, MemBuffer &out);
    void unpackThin(const byte *in, size_t n, MemBuffer &out, MemBuffer &extra);
    unsigned compressPlain(const byte *src, unsigned len, MemBuffer &dst, unsigned &u_adler,
                           unsigned &c_adler);
    void decompressPlain(const byte *src, unsigned c_len, byte *dst, unsigned u_len,
                         unsigned u_adler, unsigned c_adler);
};

/* vim:set ts=4 sw=4 et: */
