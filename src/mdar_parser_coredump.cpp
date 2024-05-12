#include <iostream>
#include <fstream>

#include "mdar_public.h"
#include "mdar_parser.h"

#include "elf.h"

namespace mdar::coredump {

bool parse_elf_modules(const char* path) {
    // TODO: implement
    return false;
}

bool prefilter(std::ifstream& data) {

    Elf64_Ehdr core_ehdr;
    data.read((char *)&core_ehdr, sizeof(Elf64_Ehdr));

    if (core_ehdr.e_type != ET_CORE) {
        std::cerr << "file is not a core dump" << std::endl;
        return false;
    }

    if (core_ehdr.e_machine != EM_X86_64) {
        std::cerr << "only 64-bit core dumps are supported" << std::endl;
        return false;
    }

    std::cout << "file is 64-bit ELF coredump" << std::endl;
    return true;
}

}
