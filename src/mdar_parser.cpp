#define NOMINMAX

#include <iostream>
#include <fstream>
#include <unordered_set>

#include "mdar_public.h"
#include "mdar_modules.h"
#include "mdar_parser_minidump.h"

#include "mdar_parser.h"

#include "pe.h"

namespace mdar {

bool parse_pe_module(memory_reader_t& reader, visited_modules_t& visited_modules,
                     uint64_t Address, const char *name) {

    IMAGE_DOS_HEADER DosHeader;
    if (!reader.get_data(Address, sizeof(IMAGE_DOS_HEADER), (uint8_t*)&DosHeader)) {
        return false;
    }

    IMAGE_NT_HEADERS32 NtHeader;
    if (!reader.get_data(Address + DosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS32), (uint8_t*)&NtHeader)) {
        return false;
    }

    if (NtHeader.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    std::vector<uint8_t> module;
    module.resize(NtHeader.OptionalHeader.SizeOfHeaders);
    if (!reader.get_data(Address, module.size(), module.data())) {
        return false;
    }

    uint64_t sections_offset = Address + DosHeader.e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + NtHeader.FileHeader.SizeOfOptionalHeader;

    for (uint32_t SecIndex = 0; SecIndex < NtHeader.FileHeader.NumberOfSections; SecIndex++) {

        IMAGE_SECTION_HEADER SectionHeader;
        if (!reader.get_data(sections_offset + SecIndex * sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER), (uint8_t*)&SectionHeader)) {
            return false;
        }

        size_t section_size = std::max(SectionHeader.SizeOfRawData, SectionHeader.Misc.VirtualSize);

        std::cout << std::format("VA: 0x{:x}", SectionHeader.VirtualAddress) << std::endl;

        module.resize(module.size() + section_size);
        if (!reader.get_data(Address + SectionHeader.VirtualAddress, section_size, module.data() + module.size() - section_size)) {
            return false;
        }
    }

    mdar_dump_module_t dump_module;
    dump_module.name = name ? name : "raw";
    dump_module.base = Address;
    dump_module.image_size = NtHeader.OptionalHeader.SizeOfImage;
    dump_module.data = module.data();
    dump_module.size = module.size();
    dump_module.gappy = true; // TODO

    MDAR_FOREACH_MODULE(id, mdar_module) {
        mdar_module.process_object(mdar_module.ctx, &dump_module);
    }

    visited_modules.insert(Address);

    return true;
}

void search_pe_modules(memory_reader_t& reader, visited_modules_t& visited_modules) {

    uint16_t magic = IMAGE_DOS_SIGNATURE;

    memory_reader_t::block_t block;
    while (reader.read_next_block(block)) {

        size_t Size = std::min(block.region_size, block.data_size);
        const uint8_t *BlockEnd = block.data + Size;

        for (auto it = block.data; it < BlockEnd; it += sizeof(magic)) {

            it = std::search(it, BlockEnd, (char*)&magic, (char*)&magic + sizeof(magic));
            if (it == BlockEnd) {
                break;
            }

            size_t offset = std::distance(block.data, it);
            if (visited_modules.find(offset) != visited_modules.end()) {
                continue;
            }

            uint64_t Address = block.base + offset;
            //std::cout << std::hex << "possible PE: 0x" << Address << std::endl;

            parse_pe_module(reader, visited_modules, Address, nullptr);
        }
    }
}

}
