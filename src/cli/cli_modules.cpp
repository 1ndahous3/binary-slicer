#include <format>
#include <fstream>
#include <iostream>

#include "cli_modules.h"

#include "yara/libyara.h"
#include "yara/error.h"
#include "yara/scan.h"

#include "mdar_public.h"


int yara_scan_cb(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data
) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* module_dump = (const mdar_dump_module_t*)user_data;
        auto* rule = (YR_RULE *)message_data;
        std::cout << std::format("[yara] detect module, addr 0x{:x}, match rule {}", module_dump->base, rule->identifier) << std::endl;
    }

    return CALLBACK_CONTINUE;
}

yara_ctx_t yara_initialize(const char *rules_filepath) {

    FILE *f = fopen(rules_filepath, "r");
    if (f == NULL) {
        printf("unable to open rules file, errno = %d\n", errno);
        return {};
    }

    int err = yr_initialize();
    if (err != ERROR_SUCCESS) {
        std::cerr << "unable to initialize YARA, error = " << err << std::endl;
        fclose(f);
        return {};
    }

    yara_ctx_t yr_ctx;

    err = yr_compiler_create(&yr_ctx.compiler);
    if (err != ERROR_SUCCESS) {
        std::cerr << "unable to create YARA compiler, error = " << err << std::endl;
        yr_finalize();
        fclose(f);
        return {};
    }

    err = yr_compiler_add_file(yr_ctx.compiler, f, nullptr, nullptr);
    if (err != ERROR_SUCCESS) {
        printf("unable to load rules, YARA error = %d\n", err);
        yr_finalize();
        fclose(f);
        return {};
    }

    err = yr_compiler_get_rules(yr_ctx.compiler, &yr_ctx.rules);
    if (err != ERROR_SUCCESS) {
        printf("unable to open rules file, YARA error = %d\n", err);
        yr_finalize();
        fclose(f);
        return {};
    }

    fclose(f);
    return yr_ctx;
}

void yara_finalize() {
    yr_finalize();
}

void yara_process_object(void *ctx, const mdar_dump_module_t *dump_module) {
    auto* yara_ctx = (yara_ctx_t*)ctx;
    std::cout << std::format("[yara] check module, addr 0x{:x}", dump_module->base) << std::endl;
    yr_rules_scan_mem(yara_ctx->rules, dump_module->data, dump_module->size, SCAN_FLAGS_REPORT_RULES_MATCHING /*| SCAN_FLAGS_REPORT_RULES_NOT_MATCHING*/, yara_scan_cb, (void*)&dump_module, 0);
}

void saver_process_object(void* ctx, const mdar_dump_module_t* dump_module) {

    std::string module_name(dump_module->name);

    auto dump_name = std::format("0x{:x}_{}", dump_module->base, module_name.substr(module_name.find_last_of("/\\") + 1));
    std::cout << std::format("[save] save module, addr 0x{:x}, dump {}", dump_module->base, dump_name) << std::endl;

    auto file = std::fstream(dump_name, std::ios::out | std::ios::binary);
    file.write((char*)dump_module->data, dump_module->size);
    file.close();
}