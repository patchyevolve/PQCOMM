#pragma once
#include "packet.h"
#include "session.h"
#include "scheduler.h"

typedef enum {
    CRYPTO_JOB_DECRYPT,
    CRYPTO_JOB_ENCRYPT,
    CRYPTO_JOB_FEC_DECRYPT
} crypto_job_type_t;

typedef struct {
    crypto_job_type_t type;
    packet_buf_t* p;
    session_t* sess;
} crypto_job_t;

int crypto_worker_start(void);
void crypto_worker_stop(void);
int crypto_worker_push(crypto_job_t* job);
int crypto_worker_pop_result(packet_buf_t** p);
