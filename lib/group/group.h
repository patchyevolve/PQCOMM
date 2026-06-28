#pragma once
#include <stdint.h>

#define GROUP_NAME_MAX   32
#define GROUP_TOPIC_MAX  128
#define GROUP_MSG_MAX    1024
#define GROUP_MAX_MEMBERS 16
#define GROUP_MAX_MSGS   100
#define GROUP_MAX_ROOMS  8

typedef struct {
    char addr[64];
    uint16_t port;
    char username[32];
    uint8_t is_online;
} group_member_t;

typedef struct {
    char text[GROUP_MSG_MAX];
    char sender[32];
    uint32_t seq;
    uint64_t timestamp_ms;
} group_message_t;

typedef struct {
    char name[GROUP_NAME_MAX];
    char topic[GROUP_TOPIC_MAX];
    uint8_t active;
    group_member_t members[GROUP_MAX_MEMBERS];
    int member_count;
    group_message_t messages[GROUP_MAX_MSGS];
    int msg_count;
    uint32_t msg_seq_counter;
} group_room_t;

int group_init(void);
int group_create(const char* name, const char* topic);
int group_join(const char* name, const char* addr, uint16_t port,
               const char* username);
int group_leave(const char* name, const char* addr, uint16_t port);
int group_add_message(const char* name, const char* sender,
                      const char* text, uint32_t seq);
int group_add_member(const char* name, const char* addr, uint16_t port,
                     const char* username);
int group_remove_member(const char* name, const char* addr, uint16_t port);
group_room_t* group_find(const char* name);
group_room_t* group_get_rooms(int* count);
void group_reset(void);
