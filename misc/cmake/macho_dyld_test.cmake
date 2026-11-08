#
# UPX "CMake" build file; see https://upx.github.io/
# Copyright (C) Markus Franz Xaver Johannes Oberhumer
#
# Tests for the macOS arm64 "macho/arm64-dyld" format.
#

set(macho_dyld_cmp "${CMAKE_CURRENT_SOURCE_DIR}/misc/cmake/macho_dyld_run_compare.cmake")

# upx_macho_dyld_roundtrip(name input [options...])
function(upx_macho_dyld_roundtrip name input)
    set(fo "--force-overwrite")
    set(wd "${CMAKE_CURRENT_BINARY_DIR}/XTesting/$<CONFIG>")
    set(packed "${wd}/upx-test-macho-dyld-${name}-packed")
    set(unpacked "${wd}/upx-test-macho-dyld-${name}-unpacked")
    set(t upx-macho-dyld)
    upx_add_test(${t}-prep-${name} "${CMAKE_COMMAND}" -E rm -f "${packed}" "${unpacked}")
    upx_add_test(${t}-pack-${name} upx --force-macos -3 ${ARGN} "${input}" ${fo} -o "${packed}")
    upx_test_depends(${t}-pack-${name} ${t}-prep-${name})
    upx_add_test(${t}-sign-${name} codesign -s - -f "${packed}")
    upx_add_test(${t}-format-${name} upx -l "${packed}")
    set_tests_properties(${t}-format-${name} PROPERTIES PASS_REGULAR_EXPRESSION "macho/arm64dyld")
    upx_add_test(${t}-run-${name} "${CMAKE_COMMAND}" -DORIG=${input} -DPACKED=${packed}
                 "-DARGS=a;b" -P "${macho_dyld_cmp}")
    upx_add_test(${t}-unpack-${name} upx -d "${packed}" ${fo} -o "${unpacked}")
    upx_add_test(${t}-compare-${name} "${CMAKE_COMMAND}" -E compare_files "${input}" "${unpacked}")
    upx_add_test(${t}-list-${name} upx -l "${packed}")
    upx_add_test(${t}-test-${name} upx -t "${packed}")
    upx_add_test(${t}-fileinfo-${name} upx --fileinfo "${packed}")
    upx_test_depends(${t}-sign-${name} ${t}-pack-${name})
    foreach(action IN ITEMS format run unpack list test fileinfo)
        upx_test_depends(${t}-${action}-${name} ${t}-sign-${name})
    endforeach()
    upx_test_depends(${t}-compare-${name} ${t}-unpack-${name})
endfunction()

function(upx_macho_dyld_test)
    set(fo "--force-overwrite")
    set(wd "${CMAKE_CURRENT_BINARY_DIR}/XTesting/$<CONFIG>")
    set(t upx-macho-dyld)
    upx_macho_dyld_roundtrip(plain "$<TARGET_FILE:upx-test-macho-dyld-plain>")
    upx_macho_dyld_roundtrip(exc "$<TARGET_FILE:upx-test-macho-dyld-exc>")
    upx_macho_dyld_roundtrip(large "$<TARGET_FILE:upx-test-macho-dyld-large>")
    if(TARGET upx-test-macho-dyld-fat)
        upx_macho_dyld_roundtrip(fat "$<TARGET_FILE:upx-test-macho-dyld-fat>")
        # the untouched x86_64 slice still runs (under Rosetta, if installed)
        set(fat "$<TARGET_FILE:upx-test-macho-dyld-fat>")
        upx_add_test(${t}-run-fat-x86_64 "${CMAKE_COMMAND}" -DORIG=${fat}
                     -DPACKED=${wd}/upx-test-macho-dyld-fat-packed -DMODE=x86_64 -P "${macho_dyld_cmp}")
        upx_test_depends(${t}-run-fat-x86_64 ${t}-sign-fat)
    endif()

    set(plain "$<TARGET_FILE:upx-test-macho-dyld-plain>")
    set(packed_plain "${wd}/upx-test-macho-dyld-plain-packed")
    upx_add_test(${t}-run-symlink "${CMAKE_COMMAND}" -DORIG=${plain} -DPACKED=${packed_plain}
                 -DMODE=symlink -P "${macho_dyld_cmp}")
    upx_test_depends(${t}-run-symlink ${t}-sign-plain)
    # no writable temp directory: exit 127 with the stub's one-line error
    upx_add_test(${t}-run-nowrite "${CMAKE_COMMAND}" -DORIG=${plain} -DPACKED=${packed_plain}
                 -DMODE=nowrite -P "${macho_dyld_cmp}")
    upx_test_depends(${t}-run-nowrite ${t}-sign-plain)

    # unpack after signing three times is still byte-identical
    set(rs "${wd}/upx-test-macho-dyld-resigned")
    upx_add_test(${t}-prep-resigned "${CMAKE_COMMAND}" -E rm -f "${rs}-packed" "${rs}-unpacked")
    upx_add_test(${t}-pack-resigned upx --force-macos -3 "${plain}" ${fo} -o "${rs}-packed")
    upx_test_depends(${t}-pack-resigned ${t}-prep-resigned)
    upx_add_test(${t}-sign-resigned sh -c
                 "codesign -s - -f '${rs}-packed' && codesign -s - -f '${rs}-packed' && codesign -s - -f '${rs}-packed'")
    upx_add_test(${t}-unpack-resigned upx -d "${rs}-packed" ${fo} -o "${rs}-unpacked")
    upx_add_test(${t}-compare-resigned "${CMAKE_COMMAND}" -E compare_files "${plain}" "${rs}-unpacked")
    upx_test_depends(${t}-sign-resigned ${t}-pack-resigned)
    upx_test_depends(${t}-unpack-resigned ${t}-sign-resigned)
    upx_test_depends(${t}-compare-resigned ${t}-unpack-resigned)

    # "upx -d" on an unpacked arm64 executable: "not packed", not a bogus error
    upx_add_test(${t}-unpack-notpacked upx -d "${plain}" ${fo} -o "${wd}/upx-test-macho-dyld-notpacked")
    set_tests_properties(${t}-unpack-notpacked PROPERTIES PASS_REGULAR_EXPRESSION "NotPackedException")

    # packing an already packed file is refused
    upx_add_test(${t}-pack-twice upx --force-macos -3 "${packed_plain}" ${fo} -o "${wd}/upx-test-macho-dyld-twice")
    set_tests_properties(${t}-pack-twice PROPERTIES PASS_REGULAR_EXPRESSION "AlreadyPackedException")
    upx_test_depends(${t}-pack-twice ${t}-sign-plain)

    # stock ld (no -headerpad): either packs and runs, or refuses cleanly
    set(nohp "$<TARGET_FILE:upx-test-macho-dyld-plain-nohp>")
    set(packed_nohp "${wd}/upx-test-macho-dyld-nohp-packed")
    upx_add_test(${t}-prep-nohp "${CMAKE_COMMAND}" -E rm -f "${packed_nohp}")
    upx_add_test(${t}-pack-nohp upx --force-macos -3 "${nohp}" ${fo} -o "${packed_nohp}")
    set_tests_properties(${t}-pack-nohp PROPERTIES
        PASS_REGULAR_EXPRESSION "Packed 1 file|no room for load commands")
    upx_add_test(${t}-sign-nohp sh -c "test ! -f '${packed_nohp}' || codesign -s - -f '${packed_nohp}'")
    upx_add_test(${t}-run-nohp "${CMAKE_COMMAND}" -DORIG=${nohp} -DPACKED=${packed_nohp}
                 -DALLOW_MISSING_PACKED=ON -P "${macho_dyld_cmp}")
    upx_test_depends(${t}-pack-nohp ${t}-prep-nohp)
    upx_test_depends(${t}-sign-nohp ${t}-pack-nohp)
    upx_test_depends(${t}-run-nohp ${t}-sign-nohp)
endfunction()
