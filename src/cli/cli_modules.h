#pragma once

#include "yara/compiler.h"
#include "yara/rules.h"

#include "mdar_public.h"

struct yara_ctx_t {
    YR_COMPILER* compiler;
    YR_RULES* rules;
};


yara_ctx_t yara_initialize(const char* rules_filepath);
void yara_finalize();
void yara_process_object(void* ctx, const mdar_dump_module_t* dump_module);

void saver_process_object(void* ctx, const mdar_dump_module_t* dump_module);
