#pragma once

#include <unordered_set>
#include <optional>
#include <vector>
#include <string>
#include <fstream>
#include <format>


namespace mdar {

using visited_modules_t = std::unordered_set<uint64_t>;

class memory_reader_t {
public:
    struct block_t {
        size_t region_size;
        size_t data_size;
        const uint8_t *data;
        uint64_t base;
        std::optional<std::vector<uint8_t>> buffer;
    };

    virtual bool get_data(uint64_t Address, size_t size, uint8_t* dst, bool allow_gaps = false) = 0;
    virtual bool read_next_block(block_t& block) = 0;

    virtual bool init(const char *path) = 0;
};

class stream_reader_t : public memory_reader_t {

    static const size_t STREAM_CHUNK = 1024;

    std::ifstream m_ist;

public:
    bool get_data(uint64_t Address, size_t size, uint8_t* dst, bool allow_gaps = false) override {
        size_t pos = m_ist.tellg();
        m_ist.seekg(Address).read((char*)dst, size);
        m_ist.seekg(pos);
        return true;
    }

    bool read_next_block(block_t& block) override {
        size_t pos = m_ist.tellg();

        block.buffer = std::vector<uint8_t>(STREAM_CHUNK);
        m_ist.read((char *)block.buffer->data(), STREAM_CHUNK);
        size_t read = (size_t)m_ist.tellg() - pos;
        if (read) {
            block.base = pos;
            block.data = block.buffer->data();
            block.data_size = block.region_size = read;
            return true;
        }

        return false;
    }

    bool init(const char* path) override {
        m_ist = std::ifstream(path, std::ios::binary);
        return true;
    }

    //size_t get_blocks_count() override {
    //    return 1;
    //}

    //block_t get_block(size_t i) override {

    //    m_ist.seekg(0, std::ios::end);
    //    size_t size = m_ist.tellg();
    //    m_ist.seekg(0);

    //    return {
    //        .region_size = size,
    //        .data_size = size,
    //        .base = 0
    //    };
    //}
};

namespace minidump {

bool prefilter(std::ifstream& data);

}

namespace coredump {

bool parse_elf_modules(const char* path);
bool prefilter(std::ifstream& data);

}

bool parse_pe_module(memory_reader_t& reader, visited_modules_t& visited_modules,
                     uint64_t Address, const char *name);
void search_pe_modules(memory_reader_t& reader, visited_modules_t& visited_modules);

}