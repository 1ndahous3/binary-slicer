#include "udmp-parser.h"
#include "mdar_parser.h"

namespace mdar {

class minidump_reader_t : public memory_reader_t {

    udmpparser::UserDumpParser m_parser;
    std::map<uint64_t, udmpparser::MemBlock_t>::const_iterator m_it_mem;
    std::map<uint64_t, udmpparser::Module_t> ::const_iterator m_it_modules;

public:
    bool get_data(uint64_t Address, size_t size, uint8_t* dst, bool allow_gaps = false) override {

        size_t read = 0;

        while (read != size) {

            Address += read;
            size_t Size = size - read;

            const auto& Block = m_parser.GetMemBlock(Address);
            if (!Block) {
                std::cerr << std::format("unable to find memory block for address 0x{:#04x}", Address) << std::endl;
                return false;
            }

            if (Block->DataSize == 0) {

                if (!allow_gaps) {
                    std::cerr << std::format("unable to get memory from the block for address 0x{:#04x}", Address) << std::endl;
                    return false;
                }

                size_t zero_bytes = std::min(Size, Block->RegionSize);
                memset(dst + read, 0, zero_bytes);

                std::cout << std::format("unable to get memory from the block for address 0x{:#04x}, zeroing {:x} bytes", Address, zero_bytes) << std::endl;

                read += zero_bytes;
                continue;
            }

            const auto OffsetFromStart = Address - Block->BaseAddress;
            const auto RemainingSize = (size_t)(Block->DataSize - OffsetFromStart);
            const auto ChunkSize = std::min(RemainingSize, Size);

            memcpy(dst + read, Block->Data + OffsetFromStart, ChunkSize);
            read += ChunkSize;
        }

        return true;
    }

    //size_t get_blocks_count() override {
    //    return m_parser.GetMem().size();
    //}

     bool read_next_block(block_t& block) override {

        auto& mem = m_parser.GetMem();
        if (m_it_mem == mem.end()) {
            return false;
        }

        block.region_size = m_it_mem->second.RegionSize;
        block.data_size = m_it_mem->second.DataSize;
        block.data = m_it_mem->second.Data;
        block.base = m_it_mem->second.BaseAddress;
        m_it_mem++;

        return true;
    }

     bool init(const char *path) override {

         if (!m_parser.Parse(path)) {
             return false;
         }

         m_it_mem = m_parser.GetMem().begin();
         m_it_modules = m_parser.GetModules().begin();
         return true;
     }

     //

     struct loaded_module_t {
         uint64_t base;
         size_t size;
         std::string name;
     };

     bool read_next_loaded_module(loaded_module_t& loaded_module) {

         auto& modules = m_parser.GetModules();
         if (m_it_modules == modules.end()) {
             return false;
         }

         loaded_module.base = m_it_modules->second.BaseOfImage;
         loaded_module.size = m_it_modules->second.SizeOfImage;
         loaded_module.name = m_it_modules->second.ModuleName;
         m_it_modules++;

         return true;
     }

};

}