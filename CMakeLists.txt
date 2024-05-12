cmake_minimum_required(VERSION 3.15)

project(mdar)

add_executable(mdar)

target_sources(mdar PRIVATE
    src/mdar_public.cpp
    src/mdar_modules.cpp
    src/mdar_parser.cpp
    src/mdar_parser_minidump.cpp
    src/mdar_parser_coredump.cpp
    src/cli/cli.cpp
    src/cli/cli_modules.cpp
    deps/core2ELF64/core2ELF64.c
)

target_include_directories(mdar PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_include_directories(mdar PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

if(MSVC)
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /showincludes")
    add_compile_options($<$<CXX_COMPILER_ID:MSVC>:/showIncludes>)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(OPENSSL_MSVC_STATIC_RT TRUE)

    foreach(CompilerFlag CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
                         CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE)
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()

    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi")
    set(CMAKE_LINKER_FLAGS_RELEASE "${CMAKE_LINKER_FLAGS_RELEASE} /DEBUG:FULL /OPT:REF /OPT:ICF")
else()
    target_link_options(mdar PRIVATE -Wl,--no-undefined)
    target_link_options(mdar PRIVATE -static-libgcc -static-libstdc++)
endif()

add_subdirectory(deps/yara)
add_subdirectory(deps/udmp-parser/src/lib)

target_link_libraries(mdar libyara)
target_link_libraries(mdar udmp-parser)

target_compile_features(mdar PRIVATE cxx_std_23)
