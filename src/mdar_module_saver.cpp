@include "structs.h"

#include <format>

#include "yara/libyara.h"
#include "yara/compiler.h"
#include "yara/rules.h"
#include "yara/scan.h"

#include <iostream>

void module_process_object_saver(const module_dump_t* module) {

    auto dump_name = std::format("0x{:x}_{}", module.base, module.name.substr(module.name.find_last_of("/\\") + 1));

    std::cout << "save dump: " << dump_name << std::endl;

    auto file = std::fstream(dump_name, std::ios::out | std::ios::binary);
    file.write((char*)module.data.data(), module.data.size());
    file.close();
}

bool module_initialize_saver(const char* arg) {

}

void module_finalize_saver() {
}

