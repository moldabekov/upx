#
# UPX "CMake" build file; see https://upx.github.io/
# Copyright (C) Markus Franz Xaver Johannes Oberhumer
#
# Run an original and a packed macOS arm64 executable with the same
# arguments and compare stdout and exit code.
#
#   cmake -DORIG=... -DPACKED=... [-DARGS=a;b] [-DMODE=normal|symlink|nowrite]
#         [-DALLOW_MISSING_PACKED=ON] -P macho_dyld_run_compare.cmake
#
#   MODE=symlink  run the packed file through a symlink from another directory
#   MODE=nowrite  run the packed file with all temp dirs write-protected
#                 (sandbox-exec); expect exit 127 and the stub's error line
#

if(NOT DEFINED MODE)
    set(MODE normal)
endif()
if(ALLOW_MISSING_PACKED AND NOT EXISTS "${PACKED}")
    message(STATUS "packed file absent and allowed: ${PACKED}")
    return()
endif()

set(packed_cmd "${PACKED}")
set(packed_wd "")
if(MODE STREQUAL "symlink")
    get_filename_component(dir "${PACKED}" DIRECTORY)
    set(link_dir "${dir}/macho-dyld-symlink-test")
    file(MAKE_DIRECTORY "${link_dir}")
    set(link "${link_dir}/packed-link")
    file(REMOVE "${link}")
    file(CREATE_LINK "${PACKED}" "${link}" SYMBOLIC)
    set(packed_cmd "./packed-link")
    set(packed_wd "${link_dir}")
endif()

if(MODE STREQUAL "x86_64")
    execute_process(COMMAND arch -x86_64 /usr/bin/true RESULT_VARIABLE rosetta)
    if(NOT rosetta EQUAL 0)
        message(STATUS "Rosetta not available: skipped")
        return()
    endif()
    execute_process(COMMAND arch -x86_64 "${ORIG}" ${ARGS} OUTPUT_VARIABLE out1 RESULT_VARIABLE rc1)
    execute_process(COMMAND arch -x86_64 "${PACKED}" ${ARGS} OUTPUT_VARIABLE out2 RESULT_VARIABLE rc2)
    if(NOT out1 STREQUAL out2 OR NOT rc1 STREQUAL rc2)
        message(FATAL_ERROR "x86_64 mismatch: '${out1}' rc=${rc1} vs '${out2}' rc=${rc2}")
    endif()
    return()
endif()

if(MODE STREQUAL "nowrite")
    set(profile "(version 1)(allow default)(deny file-write* (subpath \"/private/tmp\") (subpath \"/private/var/folders\"))")
    execute_process(COMMAND sandbox-exec -p "${profile}" "${PACKED}" ${ARGS}
                    OUTPUT_VARIABLE out ERROR_VARIABLE err RESULT_VARIABLE rc)
    string(STRIP "${err}" err)
    if(NOT rc EQUAL 127 OR NOT out STREQUAL "" OR NOT err MATCHES "upx: open failed: errno [0-9]+$")
        message(FATAL_ERROR "nowrite: rc=${rc} stdout='${out}' stderr='${err}'")
    endif()
    return()
endif()

execute_process(COMMAND "${ORIG}" ${ARGS} OUTPUT_VARIABLE out1 RESULT_VARIABLE rc1)
if(packed_wd STREQUAL "")
    execute_process(COMMAND ${packed_cmd} ${ARGS} OUTPUT_VARIABLE out2 ERROR_VARIABLE err2
                    RESULT_VARIABLE rc2)
else()
    execute_process(COMMAND ${packed_cmd} ${ARGS} WORKING_DIRECTORY "${packed_wd}"
                    OUTPUT_VARIABLE out2 ERROR_VARIABLE err2 RESULT_VARIABLE rc2)
endif()
if(NOT out1 STREQUAL out2 OR NOT rc1 STREQUAL rc2)
    message(FATAL_ERROR "mismatch: original rc=${rc1} out='${out1}'; packed rc=${rc2} out='${out2}' err='${err2}'")
endif()
message(STATUS "match: rc=${rc1}")
