#include "group.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

static group_room_t g_rooms[GROUP_MAX_ROOMS];
static int g_rooms_initialized = 0;

int group_init(void)
{
    if (g_rooms_initialized) return 0;
    memset(g_rooms, 0, sizeof(g_rooms));
    g_rooms_initialized = 1;
    return 0;
}

int group_create(const char* name, const char* topic)
{
    if (!name || !name[0]) return -1;

    /* Check if already exists */
    for (int i = 0; i < GROUP_MAX_ROOMS; i++) {
        if (g_rooms[i].active && strcmp(g_rooms[i].name, name) == 0)
            return -2;
    }

    /* Find empty slot */
    for (int i = 0; i < GROUP_MAX_ROOMS; i++) {
        if (!g_rooms[i].active) {
            snprintf(g_rooms[i].name, GROUP_NAME_MAX, "%s", name);
            snprintf(g_rooms[i].topic, GROUP_TOPIC_MAX, "%s",
                     topic ? topic : "");
            g_rooms[i].active = 1;
            g_rooms[i].member_count = 0;
            g_rooms[i].msg_count = 0;
            g_rooms[i].msg_seq_counter = 0;
            return 0;
        }
    }

    return -3; /* no room */
}

int group_join(const char* name, const char* addr, uint16_t port,
               const char* username)
{
    group_room_t* room = group_find(name);
    if (!room) return -1;

    /* Check if already member */
    for (int i = 0; i < room->member_count; i++) {
        if (strcmp(room->members[i].addr, addr) == 0 &&
            room->members[i].port == port)
            return 0; /* already joined */
    }

    if (room->member_count >= GROUP_MAX_MEMBERS) return -2;

    group_member_t* m = &room->members[room->member_count++];
    snprintf(m->addr, sizeof(m->addr), "%s", addr);
    m->port = port;
    snprintf(m->username, sizeof(m->username), "%s",
             username ? username : addr);
    m->is_online = 1;

    return 0;
}

int group_leave(const char* name, const char* addr, uint16_t port)
{
    group_room_t* room = group_find(name);
    if (!room) return -1;

    for (int i = 0; i < room->member_count; i++) {
        if (strcmp(room->members[i].addr, addr) == 0 &&
            room->members[i].port == port) {
            /* Shift remaining members */
            for (int j = i; j < room->member_count - 1; j++)
                room->members[j] = room->members[j + 1];
            room->member_count--;
            return 0;
        }
    }

    return -2; /* not found */
}

int group_add_message(const char* name, const char* sender,
                      const char* text, uint32_t seq)
{
    group_room_t* room = group_find(name);
    if (!room) return -1;

    if (room->msg_count >= GROUP_MAX_MSGS) {
        /* Shift old messages out */
        for (int i = 1; i < GROUP_MAX_MSGS; i++)
            room->messages[i - 1] = room->messages[i];
        room->msg_count = GROUP_MAX_MSGS - 1;
    }

    group_message_t* msg = &room->messages[room->msg_count++];
    snprintf(msg->text, GROUP_MSG_MAX, "%s", text ? text : "");
    snprintf(msg->sender, sizeof(msg->sender), "%s",
             sender ? sender : "unknown");
    msg->seq = seq > 0 ? seq : ++room->msg_seq_counter;
    msg->timestamp_ms = (uint64_t)time(NULL) * 1000;

    return 0;
}

int group_add_member(const char* name, const char* addr, uint16_t port,
                     const char* username)
{
    return group_join(name, addr, port, username);
}

int group_remove_member(const char* name, const char* addr, uint16_t port)
{
    return group_leave(name, addr, port);
}

group_room_t* group_find(const char* name)
{
    if (!name || !name[0]) return NULL;
    for (int i = 0; i < GROUP_MAX_ROOMS; i++) {
        if (g_rooms[i].active && strcmp(g_rooms[i].name, name) == 0)
            return &g_rooms[i];
    }
    return NULL;
}

group_room_t* group_get_rooms(int* count)
{
    if (!count) return NULL;
    *count = 0;
    for (int i = 0; i < GROUP_MAX_ROOMS; i++) {
        if (g_rooms[i].active) (*count)++;
    }
    return g_rooms;
}

void group_reset(void)
{
    memset(g_rooms, 0, sizeof(g_rooms));
    g_rooms_initialized = 0;
}
