#include "group.h"
#include "session.h"
#include <string.h>
#include <stdio.h>

/* Test: create room and verify it exists */
static int test_group_create(void)
{
    group_reset();
    group_init();

    if (group_create("test-room", "A test room") != 0) return -1;
    group_room_t* r = group_find("test-room");
    if (!r) return -2;
    if (!r->active) return -3;
    if (strcmp(r->name, "test-room") != 0) return -4;
    if (strcmp(r->topic, "A test room") != 0) return -5;
    if (r->member_count != 0) return -6;
    if (r->msg_count != 0) return -7;

    /* Duplicate name should fail */
    if (group_create("test-room", "") != -2) return -8;

    return 0;
}

/* Test: join and leave room */
static int test_group_members(void)
{
    group_reset();
    group_init();
    group_create("members-test", "");

    if (group_join("members-test", "192.168.1.10", 9001, "alice") != 0)
        return -1;
    if (group_join("members-test", "192.168.1.20", 9001, "bob") != 0)
        return -2;
    if (group_join("members-test", "192.168.1.30", 9001, "carol") != 0)
        return -3;

    group_room_t* r = group_find("members-test");
    if (!r) return -4;
    if (r->member_count != 3) return -5;

    if (strcmp(r->members[0].username, "alice") != 0) return -6;
    if (strcmp(r->members[1].username, "bob") != 0) return -7;
    if (strcmp(r->members[2].username, "carol") != 0) return -8;

    /* Duplicate join should be idempotent */
    if (group_join("members-test", "192.168.1.10", 9001, "alice") != 0)
        return -9;
    if (r->member_count != 3) return -10;

    /* Leave */
    if (group_leave("members-test", "192.168.1.10", 9001) != 0) return -11;
    if (r->member_count != 2) return -12;
    if (group_leave("members-test", "192.168.20", 9001) != -2) return -13;

    return 0;
}

/* Test: message history management */
static int test_group_messages(void)
{
    group_reset();
    group_init();
    group_create("msg-test", "");

    group_add_message("msg-test", "alice", "Hello!", 1);
    group_add_message("msg-test", "bob", "Hi Alice!", 2);
    group_add_message("msg-test", "carol", "Hey everyone!", 3);

    group_room_t* r = group_find("msg-test");
    if (!r) return -1;
    if (r->msg_count != 3) return -2;

    if (strcmp(r->messages[0].text, "Hello!") != 0) return -3;
    if (strcmp(r->messages[1].sender, "bob") != 0) return -4;
    if (strcmp(r->messages[2].text, "Hey everyone!") != 0) return -5;

    /* Verify opcode values match session.h */
    if (CTRL_GROUP_CREATE != 32) return -6;
    if (CTRL_GROUP_JOIN != 33) return -7;
    if (CTRL_GROUP_LEAVE != 34) return -8;
    if (CTRL_GROUP_MSG != 35) return -9;
    if (CTRL_GROUP_LIST != 36) return -10;

    return 0;
}

/* Test: room listing */
static int test_group_list(void)
{
    group_reset();
    group_init();
    group_create("room-a", "First room");
    group_create("room-b", "Second room");
    group_create("room-c", "Third room");

    int count = 0;
    group_room_t* rooms = group_get_rooms(&count);
    if (!rooms) return -1;
    if (count != 3) return -2;

    int found[3] = {0};
    for (int i = 0; i < count; i++) {
        if (strcmp(rooms[i].name, "room-a") == 0) found[0] = 1;
        if (strcmp(rooms[i].name, "room-b") == 0) found[1] = 1;
        if (strcmp(rooms[i].name, "room-c") == 0) found[2] = 1;
    }
    if (!found[0] || !found[1] || !found[2]) return -3;

    return 0;
}

/* Test: max capacity and rollover behavior */
static int test_group_capacity(void)
{
    group_reset();
    group_init();
    group_create("capacity-test", "");

    /* Fill to max members */
    for (int i = 0; i < GROUP_MAX_MEMBERS; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "10.0.0.%d", i + 1);
        if (group_join("capacity-test", addr, 9001, "user") != 0)
            return -1;
    }

    group_room_t* r = group_find("capacity-test");
    if (!r) return -2;
    if (r->member_count != GROUP_MAX_MEMBERS) return -3;

    /* Next join should fail */
    if (group_join("capacity-test", "10.0.0.99", 9001, "extra") != -2)
        return -4;

    return 0;
}

/* Test: message ring buffer rollover */
static int test_group_msg_rollover(void)
{
    group_reset();
    group_init();
    group_create("rollover-test", "");

    /* Add more than max messages */
    for (int i = 0; i < GROUP_MAX_MSGS + 10; i++) {
        char text[64];
        snprintf(text, sizeof(text), "msg %d", i);
        group_add_message("rollover-test", "alice", text, (uint32_t)i);
    }

    group_room_t* r = group_find("rollover-test");
    if (!r) return -1;
    if (r->msg_count != GROUP_MAX_MSGS) return -2;

    /* Oldest messages should have rolled out */
    /* First message should be msg 10 (not msg 0) */
    char expected[64];
    snprintf(expected, sizeof(expected), "msg %d", 10);
    if (strcmp(r->messages[0].text, expected) != 0) return -3;

    return 0;
}

int test_group_create_wrapper(void) { return test_group_create(); }
int test_group_members_wrapper(void) { return test_group_members(); }
int test_group_messages_wrapper(void) { return test_group_messages(); }
int test_group_list_wrapper(void) { return test_group_list(); }
int test_group_capacity_wrapper(void) { return test_group_capacity(); }
int test_group_msg_rollover_wrapper(void) { return test_group_msg_rollover(); }
