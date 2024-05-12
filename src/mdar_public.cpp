#define NOMINMAX
#include <iostream>
#include <fstream>

#include "mdar_modules.h"
#include "mdar_parser.h"
#include "mdar_parser_minidump.h"

#include "mdar_public.h"

void mdar_module_register(uint32_t id, const mdar_module_ctx2_t* ctx) {
    g_mdar_modules[id] = *(const mdar_module_ctx_t*)ctx;
}

bool mdar_initialize() {
    return true;
}

void mdar_finalize() {}

bool mdar_process_file(const char* path) {

    std::ifstream ist(path, std::ios::binary);

    uint32_t magic;
    ist.read((char*)&magic, 4);
    ist.seekg(0);

    mdar_file_type_t file_type = MDAR_FILE_UNKNOWN;

    if (magic == 0x464C457F) { // ELF
        //if (coredump::prefilter(dump)) {
        file_type = MDAR_FILE_COREDUMP_ELF64;
        //}
    }
    else if (magic == 0x504d444d) { // 'MDMP'
        //if (minidump::prefilter(dump)) {
        file_type = MDAR_FILE_MINIDUMP;
        //}
    }

    switch (file_type)
    {
    case MDAR_FILE_MINIDUMP:
        mdar_minidump_process_pe_modules(path);
        break;
    case MDAR_FILE_COREDUMP_ELF64:
        mdar_coredump_process_elf_modules(path);
        break;
    default:
        mdar::stream_reader_t reader;
        if (!reader.init(path)) {
            std::cerr << "unable to init stream" << std::endl;
            return false;
        }

        mdar::visited_modules_t visited_modules;
        mdar::search_pe_modules(reader, visited_modules);

        break;
    }

    return true;
}

bool mdar_minidump_process_pe_modules(const char *path) {

    mdar::minidump_reader_t reader;
    mdar::visited_modules_t visited_modules;

    if (!reader.init(path)) {
        std::cerr << "unable to parse Windows minidump" << std::endl;
        return false;
    }

    // get modules from list

    std::cout << "\nprocess listed modules:" << std::endl;

    mdar::minidump_reader_t::loaded_module_t loaded_module;
    while (reader.read_next_loaded_module(loaded_module)) {

        //std::cout << std::format("listed module: address = 0x{:#04x}, module = {} ", ModuleInfo.BaseOfImage, ModuleInfo.ModuleName) << std::endl;

        bool res = mdar::parse_pe_module(reader, visited_modules, loaded_module.base, loaded_module.name.c_str());
        if (!res) {
            std::cerr << std::format("unable to dump module: address = 0x{:#04x}, module = {} ", loaded_module.base, loaded_module.name) << std::endl;
            continue;
        }
    }

    // find modules in all VA

    std::cout << "\nprocess unlisted modules:" << std::endl;
    mdar::search_pe_modules(reader, visited_modules);

    return true;
}


bool mdar_coredump_process_elf_modules(const char *path) {
    return mdar::coredump::parse_elf_modules(path);
}