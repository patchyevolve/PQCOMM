#include "file_transfer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

uint32_t file_checksum(const uint8_t* data, uint32_t len)
{
    uint32_t sum = 0;
    for (uint32_t i = 0; i < len; i++)
        sum = (sum * 31) + data[i];
    return sum;
}

void file_transfer_init(file_transfer_ctx_t* ft)
{
    memset(ft, 0, sizeof(*ft));
}

void file_transfer_cleanup(file_transfer_ctx_t* ft)
{
    memset(ft, 0, sizeof(*ft));
}

int file_send_start(file_transfer_ctx_t* ft, const char* filepath)
{
    if (!ft || !filepath) return -1;
    if (ft->send_count >= FILE_TRANSFER_MAX) return -1;

    struct stat st;
    if (stat(filepath, &st) != 0) return -1;
    if (st.st_size == 0) return -1;

    file_send_t* s = &ft->sends[ft->send_count];
    memset(s, 0, sizeof(*s));
    snprintf(s->path, sizeof(s->path), "%s", filepath);

    const char* basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;
    snprintf(s->meta.filename, sizeof(s->meta.filename), "%s", basename);
    s->meta.total_size = (uint32_t)st.st_size;
    s->meta.total_chunks = ((uint32_t)st.st_size + FILE_CHUNK_SIZE - 1) / FILE_CHUNK_SIZE;
    s->meta.active = 1;

    uint8_t buf[FILE_CHUNK_SIZE];
    uint32_t total_checksum = 0;
    FILE* f = fopen(filepath, "rb");
    if (!f) return -1;
    uint32_t remaining = s->meta.total_size;
    while (remaining > 0) {
        uint32_t rd = remaining > FILE_CHUNK_SIZE ? FILE_CHUNK_SIZE : remaining;
        if (fread(buf, 1, rd, f) != rd) { fclose(f); return -1; }
        total_checksum = (total_checksum * 31) + file_checksum(buf, rd);
        remaining -= rd;
    }
    fclose(f);
    s->meta.checksum = total_checksum;

    ft->send_count++;
    return ft->send_count - 1;
}

int file_send_chunk(file_transfer_ctx_t* ft, int send_idx, uint8_t* buf, uint32_t* out_len)
{
    if (!ft || send_idx < 0 || send_idx >= ft->send_count) return -1;
    file_send_t* s = &ft->sends[send_idx];
    if (!s->active || s->chunks_sent >= s->meta.total_chunks) return -1;

    FILE* f = fopen(s->path, "rb");
    if (!f) return -1;
    fseek(f, s->chunks_sent * FILE_CHUNK_SIZE, SEEK_SET);
    uint32_t remaining = s->meta.total_size - s->chunks_sent * FILE_CHUNK_SIZE;
    uint32_t rd = remaining > FILE_CHUNK_SIZE ? FILE_CHUNK_SIZE : remaining;
    if (fread(buf, 1, rd, f) != rd) { fclose(f); return -1; }
    fclose(f);

    *out_len = rd;
    s->chunks_sent++;
    return (int)(s->chunks_sent >= s->meta.total_chunks) ? 1 : 0;
}

int file_send_finished(file_transfer_ctx_t* ft, int send_idx)
{
    if (!ft || send_idx < 0 || send_idx >= ft->send_count) return 0;
    file_send_t* s = &ft->sends[send_idx];
    return s->active && s->chunks_sent >= s->meta.total_chunks;
}

int file_recv_start(file_transfer_ctx_t* ft, const char* filename, uint32_t total_size,
                    uint32_t total_chunks, uint32_t checksum)
{
    if (!ft || !filename) return -1;
    if (ft->recv_count >= FILE_TRANSFER_MAX) return -1;
    if (total_chunks > FILE_MAX_CHUNKS) return -1;

    file_recv_t* r = &ft->recvs[ft->recv_count];
    memset(r, 0, sizeof(*r));
    snprintf(r->meta.filename, sizeof(r->meta.filename), "%s", filename);
    r->meta.total_size = total_size;
    r->meta.total_chunks = total_chunks;
    r->meta.checksum = checksum;
    r->meta.active = 1;
    r->active = 1;

    ft->recv_count++;
    return ft->recv_count - 1;
}

int file_recv_chunk(file_transfer_ctx_t* ft, int recv_idx, const uint8_t* data, uint32_t len,
                    uint32_t chunk_seq)
{
    if (!ft || recv_idx < 0 || recv_idx >= ft->recv_count) return -1;
    file_recv_t* r = &ft->recvs[recv_idx];
    if (!r->active) return -1;
    if (chunk_seq >= r->meta.total_chunks) return -1;
    if (!r->path[0]) {
        snprintf(r->path, sizeof(r->path), "/tmp/ssm_file_%s.part", r->meta.filename);
    }
    FILE* f = fopen(r->path, "r+b");
    if (!f) {
        f = fopen(r->path, "wb");
        if (!f) return -1;
        fclose(f);
        f = fopen(r->path, "r+b");
        if (!f) return -1;
    }
    fseek(f, chunk_seq * FILE_CHUNK_SIZE, SEEK_SET);
    fwrite(data, 1, len, f);
    fclose(f);
    r->chunks_recvd++;
    return (int)(r->chunks_recvd >= r->meta.total_chunks) ? 1 : 0;
}

int file_recv_finish(file_transfer_ctx_t* ft, int recv_idx, const char* save_dir)
{
    if (!ft || recv_idx < 0 || recv_idx >= ft->recv_count) return -1;
    file_recv_t* r = &ft->recvs[recv_idx];
    if (!r->active) return -1;
    if (r->chunks_recvd < r->meta.total_chunks) return -1;

    uint32_t total_checksum = 0;
    uint8_t buf[FILE_CHUNK_SIZE];
    FILE* f = fopen(r->path, "rb");
    if (!f) return -1;
    uint32_t remaining = r->meta.total_size;
    while (remaining > 0) {
        uint32_t rd = remaining > FILE_CHUNK_SIZE ? FILE_CHUNK_SIZE : remaining;
        if (fread(buf, 1, rd, f) != rd) { fclose(f); return -1; }
        total_checksum = (total_checksum * 31) + file_checksum(buf, rd);
        remaining -= rd;
    }
    fclose(f);

    if (total_checksum != r->meta.checksum) {
        unlink(r->path);
        return -1;
    }

    char final_path[FILE_PATH_MAX];
    if (save_dir)
        snprintf(final_path, sizeof(final_path), "%s/%s", save_dir, r->meta.filename);
    else
        snprintf(final_path, sizeof(final_path), "%s", r->path);
    rename(r->path, final_path);
    r->active = 0;
    return 0;
}
