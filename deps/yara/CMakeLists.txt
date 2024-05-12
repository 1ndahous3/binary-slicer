project("libyara" C)

add_library(libyara STATIC)

target_include_directories(libyara PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

set(CMAKE_CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/yara/libyara)

target_include_directories(libyara PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(libyara PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_sources(libyara PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/grammar.c
    ${CMAKE_CURRENT_SOURCE_DIR}/lexer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hex_grammar.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hex_lexer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/re_grammar.c
    ${CMAKE_CURRENT_SOURCE_DIR}/re_lexer.c

    ${CMAKE_CURRENT_SOURCE_DIR}/ahocorasick.c
    ${CMAKE_CURRENT_SOURCE_DIR}/arena.c
    ${CMAKE_CURRENT_SOURCE_DIR}/atoms.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bitmask.c
    ${CMAKE_CURRENT_SOURCE_DIR}/compiler.c
    ${CMAKE_CURRENT_SOURCE_DIR}/endian.c
    ${CMAKE_CURRENT_SOURCE_DIR}/exec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/exefiles.c
    ${CMAKE_CURRENT_SOURCE_DIR}/filemap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/libyara.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules.c
    ${CMAKE_CURRENT_SOURCE_DIR}/notebook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/object.c
    ${CMAKE_CURRENT_SOURCE_DIR}/parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/proc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/proc/none.c
    ${CMAKE_CURRENT_SOURCE_DIR}/re.c
    ${CMAKE_CURRENT_SOURCE_DIR}/rules.c
    ${CMAKE_CURRENT_SOURCE_DIR}/scan.c
    ${CMAKE_CURRENT_SOURCE_DIR}/scanner.c
    ${CMAKE_CURRENT_SOURCE_DIR}/simple_str.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sizedstr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/stack.c
    ${CMAKE_CURRENT_SOURCE_DIR}/stopwatch.c
    ${CMAKE_CURRENT_SOURCE_DIR}/stream.c
    ${CMAKE_CURRENT_SOURCE_DIR}/strutils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/threading.c

    ${CMAKE_CURRENT_SOURCE_DIR}/modules/console/console.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/dotnet/dotnet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/elf/elf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/hash/hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/math/math.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/pe/authenticode-parser/authenticode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/pe/authenticode-parser/certificate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/pe/authenticode-parser/countersignature.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/pe/authenticode-parser/helper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/pe/authenticode-parser/structs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/pe/pe.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/pe/pe_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/string/string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/tests/tests.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/time/time.c

    ${CMAKE_CURRENT_SOURCE_DIR}/tlshc/tlsh.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tlshc/tlsh_impl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tlshc/tlsh_util.c
)

target_compile_definitions(libyara PUBLIC HAVE_LIBCRYPTO USE_NO_PROC DOTNET_MODULE HASH_MODULE)
target_compile_definitions(libyara PRIVATE BUCKETS_256)

if(MSVC)
    target_compile_options(libyara PRIVATE /W3 /Zi)
    target_compile_definitions(libyara PUBLIC _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(libyara PRIVATE -Wall)
endif()

set_target_properties(libyara PROPERTIES
                      POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Target 'libyara' would produce liblibyara filename, so override it.
set_target_properties(libyara PROPERTIES PREFIX "")
set_target_properties(libyara PROPERTIES OUTPUT_NAME "libyara")

target_include_directories(libyara PRIVATE ${OPENSSL_INCLUDE_DIR})
message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

target_link_libraries(libyara Threads::Threads)
target_link_libraries(libyara OpenSSL::Crypto)
