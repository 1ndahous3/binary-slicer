#ifndef MDAR_PUBLIC_H
#define MDAR_PUBLIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

enum mdar_file_type_t {
    MDAR_FILE_UNKNOWN,
    MDAR_FILE_MINIDUMP,
    MDAR_FILE_COREDUMP_ELF64
};

typedef struct _mdar_dump_module_t {
    // meta
    const char *name;
    uint64_t base;
    size_t image_size;
    // data
    const uint8_t *data;
    size_t size;
    bool gappy;
} mdar_dump_module_t;


typedef void(*pfn_mdar_module_process_object_t)(void *ctx, const mdar_dump_module_t *dump_module);

typedef struct _mdar_module_ctx_t {
    void* ctx;
    pfn_mdar_module_process_object_t process_object;
} mdar_module_ctx_t;

typedef struct _mdar_module_ctx2_t {
    void* ctx;
    pfn_mdar_module_process_object_t process_object;
} mdar_module_ctx2_t; // TODO: fix

//void mdar_module_register(uint32_t id, const struct mdar_module_ctx_t* ctx);
//void mdar_module_register(uint32_t id, const void* ctx);
void mdar_module_register(uint32_t id, const mdar_module_ctx2_t* ctx);

bool mdar_initialize();
void mdar_finalize();


//bool mdar_minidump_prefilter(const char* path);
//bool mdar_coredump_prefilter(const char* path);

bool mdar_process_file(const char *path);
bool mdar_minidump_process_pe_modules(const char *path);
bool mdar_coredump_process_elf_modules(const char *path);

#ifdef __cplusplus
}
#endif

#endif // MDAR_PUBLIC_H