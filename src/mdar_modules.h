#pragma once


#include <unordered_map>

#include "mdar_public.h"

extern std::unordered_map<uint32_t, mdar_module_ctx_t> g_mdar_modules;

#define MDAR_FOREACH_MODULE(ID, MODULE) for (auto& [ID, MODULE] : g_mdar_modules)