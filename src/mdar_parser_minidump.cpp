#define NOMINMAX

#include <iostream>
#include <fstream>
#include <unordered_set>

#include "mdar_public.h"
#include "mdar_modules.h"
#include "mdar_parser_minidump.h"

namespace mdar::minidump {

bool prefilter(std::ifstream& data) {

    udmpparser::dmp::Header_t mdmp_hdr;
    data.read((char *)&mdmp_hdr, sizeof(udmpparser::dmp::Header_t));
    data.seekg(0);

    if (!mdmp_hdr.LooksGood()) {
        std::cerr << "invalid Windows minidump" << std::endl;
        return false;
    }

    return true;
}

}
