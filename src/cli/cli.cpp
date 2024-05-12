#define NOMINMAX

#include <algorithm>
#include <iterator>
#include <iostream>
#include <fstream>
#include <cstdlib>

#include "cli_modules.h"
#include "mdar_public.h"

char usage[] = "Usage: mdar rule.yar process_dump";


extern "C" int main2(int argc, char** argv);

int main(int argc, char* argv[]) {

    //return main2(argc, argv);

    if (argc != 3) {
       puts(usage);
       return EXIT_FAILURE;
    }

    auto yr_ctx = yara_initialize(argv[2]);
    if (yr_ctx.compiler == NULL) {
        return EXIT_FAILURE;
    }

    mdar_module_ctx2_t module_ctx;
    module_ctx.ctx = &yr_ctx;
    module_ctx.process_object = &yara_process_object;
    mdar_module_register('yara', &module_ctx);

    //module_ctx.ctx = nullptr;
    //module_ctx.process_object = &saver_process_object;
    //mdar_module_register('save', &module_ctx);

    mdar_process_file(argv[1]);

    //yara_finalize();

    return EXIT_SUCCESS;
}