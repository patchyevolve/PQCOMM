#pragma once
#include <stdint.h>

#define FILE_CHUNK_SIZE 1024
#define FILE_NAME_MAX 256
#define FILE_PATH_MAX 512
#define FILE_MAX_CHUNKS 65536

typedef struct {
    char filename[FILE_NAME_MAX];
    uint32_t total_size;
    uint32_t total_chunks;
    uint32_t checksum;
    int active;
} file_meta_t;

typedef struct {
    file_meta_t meta;
    char path[FILE_PATH_MAX];
    uint32_t chunks_recvd;
    int active;
} file_recv_t;

typedef struct {
    char path[FILE_PATH_MAX];
    file_meta_t meta;
    uint32_t chunks_sent;
    int active;
} file_send_t;

#define FILE_TRANSFER_MAX 4

typedef struct {
    file_send_t sends[FILE_TRANSFER_MAX];
    file_recv_t recvs[FILE_TRANSFER_MAX];
    int send_count;
    int recv_count;
} file_transfer_ctx_t;

uint32_t file_checksum(const uint8_t* data, uint32_t len);
int file_send_start(file_transfer_ctx_t* ft, const char* filepath);
int file_send_chunk(file_transfer_ctx_t* ft, int send_idx, uint8_t* buf, uint32_t* out_len);
int file_send_finished(file_transfer_ctx_t* ft, int send_idx);
int file_recv_start(file_transfer_ctx_t* ft, const char* filename, uint32_t total_size,
                    uint32_t total_chunks, uint32_t checksum);
int file_recv_chunk(file_transfer_ctx_t* ft, int recv_idx, const uint8_t* data, uint32_t len,
                    uint32_t chunk_seq);
int file_recv_finish(file_transfer_ctx_t* ft, int recv_idx, const char* save_dir);
void file_transfer_init(file_transfer_ctx_t* ft);
void file_transfer_cleanup(file_transfer_ctx_t* ft);
