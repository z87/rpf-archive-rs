#ifndef RPF_ARCHIVE_H
#define RPF_ARCHIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define RPF_API __declspec(dllimport)
#else
#define RPF_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t rpf_status;

enum {
    RPF_STATUS_OK = 0,
    RPF_STATUS_ERROR = 1,
    RPF_STATUS_INVALID_ARGUMENT = 2,
    RPF_STATUS_INVALID_HANDLE = 3,
    RPF_STATUS_BAD_ARCHIVE = 4,
    RPF_STATUS_BAD_KEY = 5,
    RPF_STATUS_UNSUPPORTED = 6,
    RPF_STATUS_OUT_OF_BOUNDS = 7,
    RPF_STATUS_PANIC = 8,
};

typedef uint32_t rpf_entry_kind;

enum {
    RPF_ENTRY_KIND_DIRECTORY = 0,
    RPF_ENTRY_KIND_BINARY_FILE = 1,
    RPF_ENTRY_KIND_RESOURCE_FILE = 2,
};

typedef struct rpf_gta_keys rpf_gta_keys;

typedef struct rpf_archive_handle rpf_archive_handle;

struct rpf_archive_entry {
    const char* name;
    rpf_entry_kind kind;
    uint64_t size;
    uint64_t offset;
    uint64_t uncompressed_size;
    uint32_t is_encrypted;
    uint32_t system_flags;
    uint32_t graphics_flags;
};

typedef struct rpf_archive_entry rpf_archive_entry;

RPF_API const char* rpf_get_last_error(void);
RPF_API void rpf_clear_last_error(void);

RPF_API rpf_status rpf_keys_load_from_embedded(const uint8_t* aes_key, rpf_gta_keys** out);
RPF_API rpf_status rpf_keys_extract_from_exe(const char* exe_path, rpf_gta_keys** out);
RPF_API rpf_status rpf_keys_get_aes_key(const rpf_gta_keys* keys, uint8_t out_aes_key[32]);
RPF_API rpf_status rpf_keys_get_awc_key(const rpf_gta_keys* keys, uint32_t out_awc_key[4]);
RPF_API rpf_status rpf_keys_close(rpf_gta_keys* keys);

RPF_API rpf_status rpf_archive_open(const uint8_t* data, size_t data_len, const char* name, const rpf_gta_keys* keys, rpf_archive_handle** out);
RPF_API rpf_status rpf_archive_open_img1(const uint8_t* dir_data, size_t dir_len, const char* name, rpf_archive_handle** out);
RPF_API rpf_status rpf_archive_close(rpf_archive_handle* handle);

RPF_API size_t rpf_archive_entry_count(const rpf_archive_handle* handle);
RPF_API rpf_status rpf_archive_entry_get(const rpf_archive_handle* handle, size_t index, rpf_archive_entry* out);

#ifdef __cplusplus
}
#endif

#endif
