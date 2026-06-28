#include "transport_engine.h"
#include "tui.h"
#include "tui_screen.h"
#include "tui_input.h"
#include "toml_config.h"
#include "identity.h"
#include "secure_store.h"
#include "lan_discovery.h"
#include "connection_manager.h"
#include "group.h"
#include "session.h"
#include "monitor.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#ifndef _WIN32
#include <unistd.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

static int g_transport_started = 0;

static int start_transport(tui_t* t, int argc, char** argv)
{
    transport_config_t config;
    memset(&config, 0, sizeof(config));
    config.local_port = 9001;
    config.local_port_alt = 9003;
    config.discovery_port = 9009;
    config.discovery_enabled = 1;
    config.fec_enabled = 1;
    config.fec_group_size = 4;
    config.multipath_enabled = 0;
    config.path_count = 1;
    config.handshake_timeout_ms = 5000;
    config.heartbeat_interval_ms = 1000;
    config.reconnect_timeout_ms = 5000;
    config.max_reconnect_attempts = 3;

    const char* cfg_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            cfg_path = argv[++i];
    }
    if (!cfg_path) cfg_path = getenv("CONFIG_FILE");
    if (!cfg_path) cfg_path = "transport.toml";

    config_t toml_cfg;
    if (config_load(&toml_cfg, cfg_path) == 0) {
        config.local_port = toml_cfg.local_port;
        config.local_port_alt = toml_cfg.local_port_alt;
        config.discovery_port = toml_cfg.discovery_port;
        config.discovery_enabled = toml_cfg.discovery_enabled;
        config.multipath_enabled = toml_cfg.multipath_enabled;
        config.path_count = toml_cfg.path_count;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            config.local_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--port-alt") == 0 && i + 1 < argc)
            config.local_port_alt = (uint16_t)atoi(argv[++i]);
    }

    lan_discovery_set_username(t->username);

    if (transport_init(&config) != 0) {
        tui_add_log(t, "transport_init failed");
        return -1;
    }

    g_transport_started = 1;
    return 0;
}

static void handle_transport_events(tui_t* t)
{
    transport_event_t ev;
    while (transport_poll_event(&ev) > 0) {
        if (ev.type == EVENT_CHAT_RECEIVED) {
            tui_add_chat(t, ev.data.chat.text, ev.data.chat.sender_port, 0);
            if (t->screen != SCREEN_CHAT) t->unread_count++;
        }
        else if (ev.type == EVENT_CONNECTION_STATE_CHANGED) {
            if (ev.data.conn_state.new_state == CONN_LOCKED)
                tui_add_chat(t, "Session locked (PQ encrypted)", 0, 0);
            tui_event_journal_add(t, "connection",
                                  ev.data.conn_state.new_state == CONN_LOCKED ? "session locked" : "state changed");
        } else if (ev.type == EVENT_CONNECT_REQUEST) {
            t->show_conn_popup = 1;
            t->conn_popup_selection = 0;
            snprintf(t->conn_req_addr, sizeof(t->conn_req_addr), "%s", ev.data.conn_req.addr);
            t->conn_req_port = ev.data.conn_req.port;
            snprintf(t->conn_req_username, sizeof(t->conn_req_username), "%s", ev.data.conn_req.username);
            snprintf(t->conn_req_display, sizeof(t->conn_req_display), "%s", ev.data.conn_req.display_name);
            t->dirty = 1;
            tui_event_journal_add(t, "connection", "incoming connect request");
        } else if (ev.type == EVENT_CONNECT_ACCEPTED) {
            transport_connect(ev.data.conn_req.addr, ev.data.conn_req.port);
            t->screen = SCREEN_CHAT;
            snprintf(t->chat_partner, sizeof(t->chat_partner), "%s", ev.data.conn_req.username);
            tui_add_chat(t, "Connecting...", 0, 0);
            t->dirty = 1;
            tui_event_journal_add(t, "connection", "connect accepted");
        } else if (ev.type == EVENT_CONNECT_DECLINED) {
            tui_add_chat(t, "Connection declined", 0, 0);
            t->dirty = 1;
            tui_event_journal_add(t, "connection", "connect declined");
        } else if (ev.type == EVENT_AUDIO_CALL_REQUEST) {
            t->show_call_popup = 1;
            t->call_popup_type = 0;
            t->call_popup_selection = 0;
            snprintf(t->call_req_peer, sizeof(t->call_req_peer), "%s", ev.data.call_req.peer_username);
            t->dirty = 1;
        } else if (ev.type == EVENT_VIDEO_CALL_REQUEST) {
            t->show_call_popup = 1;
            t->call_popup_type = 1;
            t->call_popup_selection = 0;
            snprintf(t->call_req_peer, sizeof(t->call_req_peer), "%s", ev.data.call_req.peer_username);
            t->dirty = 1;
        } else if (ev.type == EVENT_AUDIO_CALL_ACCEPTED) {
            tui_add_chat(t, "\033[1;35m[Audio call connected]\033[0m", 0, 0);
            t->audio_active = 1;
            t->dirty = 1;
        } else if (ev.type == EVENT_AUDIO_CALL_ENDED) {
            tui_add_chat(t, "\033[1;35m[Audio call ended]\033[0m", 0, 0);
            t->audio_active = 0;
            t->dirty = 1;
        } else if (ev.type == EVENT_VIDEO_CALL_ACCEPTED) {
            tui_add_chat(t, "\033[1;36m[Video call connected]\033[0m", 0, 0);
            t->video_active = 1;
            t->dirty = 1;
        } else if (ev.type == EVENT_VIDEO_CALL_ENDED) {
            tui_add_chat(t, "\033[1;36m[Video call ended]\033[0m", 0, 0);
            t->video_active = 0;
            t->dirty = 1;
        } else if (ev.type == EVENT_FILE_TRANSFER_COMPLETE) {
            tui_add_chat(t, "\033[1;32m[File transfer complete]\033[0m", 0, 0);
            t->dirty = 1;
        } else if (ev.type == EVENT_FILE_TRANSFER_FAILED) {
            tui_add_chat(t, "\033[1;31m[File transfer failed]\033[0m", 0, 0);
            t->dirty = 1;
        } else if (ev.type == EVENT_FILE_TRANSFER_PROGRESS) {
            char msg[256];
            snprintf(msg, sizeof(msg), "\033[1;33m[File: %s %u/%u]\033[0m",
                     ev.data.file.filename, ev.data.file.progress, ev.data.file.total_size);
            tui_add_chat(t, msg, 0, 0);
            t->dirty = 1;
        } else if (ev.type == EVENT_TYPING) {
            if (t->chat_partner[0]) {
                snprintf(t->typing_peer, sizeof(t->typing_peer), "%s", t->chat_partner);
                t->typing_tick = 4;
                t->dirty = 1;
            }
        } else if (ev.type == EVENT_DELIVERY_ACK) {
            for (int i = t->chat_count - 1; i >= 0; i--) {
                if (t->chat_lines[i].is_self && t->chat_lines[i].status == 0) {
                    t->chat_lines[i].status = 1;
                    break;
                }
            }
            t->dirty = 1;
        } else if (ev.type == EVENT_READ_ACK) {
            for (int i = t->chat_count - 1; i >= 0; i--) {
                if (t->chat_lines[i].is_self && t->chat_lines[i].status == 1) {
                    t->chat_lines[i].status = 2;
                    break;
                }
            }
            t->dirty = 1;
        }
    }
}

static int run_tui(int argc, char** argv)
{
    tui_t tui;
    identity_t id;
    memset(&id, 0, sizeof(id));
    tui_init(&tui);
    tui_term_init(&tui);

    const char* config_dir = getenv("HOME");
    char path[512];
    if (config_dir)
        snprintf(path, sizeof(path), "%s/.config/ssm", config_dir);
    else
        snprintf(path, sizeof(path), "/tmp/.config/ssm");

    int existing_identity = 0;
    if (identity_init(&id, path) == 0 && id.initialized) {
        snprintf(tui.username, sizeof(tui.username), "%s", id.username);
        snprintf(tui.display_name, sizeof(tui.display_name), "%s", id.display_name);
        tui.identity = id;
        tui.identity_ready = 1;
        tui.screen = SCREEN_PEER_LIST;
        tui.dirty = 1;
        existing_identity = 1;
    }

    if (existing_identity) {
        start_transport(&tui, argc, argv);
    }

    group_init();
    monitor_start();

    tui_render(&tui);
    int frame = 0;

    while (tui.running) {
        if (g_transport_started) {
            handle_transport_events(&tui);
        }

        if (tui.typing_flag && tui.conn_info.state == CONN_LOCKED) {
            transport_send_typing();
            tui.typing_flag = 0;
        }

        if (tui.typing_tick > 0) {
            tui.typing_tick--;
            if (tui.typing_tick == 0) tui.dirty = 1;
        }

        conn_info_t info;
        transport_get_connection_info(&info);
        tui_update_info(&tui, &info);

        if (g_transport_started && frame % 10 == 0) {
            lan_discovery_trigger_scan();
            uint64_t now_ms = (uint64_t)time(NULL) * 1000;
            connection_manager_mark_stale(now_ms, 30000);

            peer_entry_t peers[32];
            int n = transport_get_peer_list(peers, 32);
            if (n != tui.peer_count || (n > 0 && memcmp(tui.peers, peers, (size_t)n * sizeof(peer_entry_t)) != 0)) {
                tui.peer_count = n;
                if (n > 0) memcpy(tui.peers, peers, (size_t)n * sizeof(peer_entry_t));
                tui.dirty = 1;
            }
        }

        int input = tui_input_poll(&tui, 200);

        /* Handle mouse clicks */
        if (input >= -202 && input <= -98 && tui.mouse_event) {
            int mx = tui.mouse_last_x;
            int my = tui.mouse_last_y;
            tui.mouse_event = 0;

            if (input <= -100 && input >= -102) {
                int btn = -(input + 100);
                if (tui.screen == SCREEN_PEER_LIST && btn == 0) {
                    int row = my - 4;
                    if (row >= 0 && row < tui.peer_count - tui.peer_scroll) {
                        int idx = tui.peer_scroll + row;
                        if (idx < tui.peer_count) {
                            tui.peer_selected = idx;
                            peer_entry_t* p = &tui.peers[idx];
                            if (!p->is_connected) {
                                transport_send_connect_request(p->addr, p->port,
                                                                tui.username, tui.display_name);
                                tui.screen = SCREEN_CHAT;
                                snprintf(tui.chat_partner, sizeof(tui.chat_partner),
                                         "%s", p->username[0] ? p->username : p->addr);
                                tui_add_chat(&tui, "Connection request sent...", 0, 0);
                            } else {
                                tui.screen = SCREEN_CHAT;
                                snprintf(tui.chat_partner, sizeof(tui.chat_partner),
                                         "%s", p->username[0] ? p->username : p->addr);
                            }
                            tui.unread_count = 0;
                            tui.dirty = 1;
                        }
                    }
                } else if (tui.screen == SCREEN_GROUP && btn == 0) {
                    int sw = 20;
                    if (sw > tui.width / 4) sw = tui.width / 4;
                    if (sw < 12) sw = 12;
                    int mw = 20;
                    if (mw > tui.width / 4) mw = tui.width / 4;
                    if (mw < 12) mw = 12;
                    if (mx <= sw) tui.group_focus = GROUP_FOCUS_ROOMS;
                    else if (mx >= tui.width - mw) tui.group_focus = GROUP_FOCUS_MEMBERS;
                    else tui.group_focus = GROUP_FOCUS_CHAT;
                    tui.dirty = 1;
                }
            } else if (input <= -199 && input >= -201) {
                int dir = (input == -199) ? 1 : -1;
                if (tui.screen == SCREEN_PEER_LIST) {
                    if (dir > 0 && tui.peer_selected < tui.peer_count - 1) {
                        tui.peer_selected++;
                        if (tui.peer_selected - tui.peer_scroll >= tui.height - 5)
                            tui.peer_scroll++;
                        tui.dirty = 1;
                    } else if (dir < 0 && tui.peer_selected > 0) {
                        tui.peer_selected--;
                        if (tui.peer_selected < tui.peer_scroll)
                            tui.peer_scroll--;
                        tui.dirty = 1;
                    }
                } else if (tui.screen == SCREEN_GROUP && tui.group_focus == GROUP_FOCUS_ROOMS) {
                    int count;
                    group_get_rooms(&count);
                    if (dir > 0 && tui.group_room_scroll < count - 1) tui.group_room_scroll++;
                    else if (dir < 0 && tui.group_room_scroll > 0) tui.group_room_scroll--;
                    tui.dirty = 1;
                } else if (tui.screen == SCREEN_GROUP && tui.group_focus == GROUP_FOCUS_MEMBERS) {
                    group_room_t* room = tui.current_room[0] ? group_find(tui.current_room) : NULL;
                    if (room) {
                        if (dir > 0 && tui.group_member_scroll < room->member_count - 1)
                            tui.group_member_scroll++;
                        else if (dir < 0 && tui.group_member_scroll > 0)
                            tui.group_member_scroll--;
                        tui.dirty = 1;
                    }
                }
            }
        }

        /* /commands — only process in chat or peer list */
        if (input >= 1 && tui.input_len > 0) {
            tui.input_buf[tui.input_len] = '\0';
            if (strncmp(tui.input_buf, "/connect ", 9) == 0) {
                char ip[64] = {0};
                int port = 0;
                if (sscanf(tui.input_buf + 9, "%63s %d", ip, &port) == 2 && port > 0 && port < 65536) {
                    transport_send_connect_request(ip, (uint16_t)port, tui.username, tui.display_name);
                    tui.screen = SCREEN_CHAT;
                    snprintf(tui.chat_partner, sizeof(tui.chat_partner), "%s:%d", ip, port);
                    tui_add_chat(&tui, "Connection request sent...", 0, 0);
                } else {
                    tui_add_chat(&tui, "Usage: /connect <ip> <port>", 0, 0);
                }
                tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
                goto done_input;
            }
            if (strcmp(tui.input_buf, "/fingerprint") == 0 && tui.identity_ready) {
                char fp[128];
                identity_get_fingerprint(&id, fp, sizeof(fp));
                tui_add_chat(&tui, fp, 0, 0);
                tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
                goto done_input;
            }
            if (strcmp(tui.input_buf, "/mykey") == 0 && tui.identity_ready) {
                char keyhex[128];
                identity_get_key_hex(&id, keyhex, sizeof(keyhex));
                tui_add_chat(&tui, keyhex, 0, 0);
                tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
                goto done_input;
            }
            if (strcmp(tui.input_buf, "/export") == 0 && tui.identity_ready) {
                char export_path[512];
                snprintf(export_path, sizeof(export_path), "%s/identity_export.dat", path);
                if (identity_export_key(&id, export_path) == 0)
                    tui_add_chat(&tui, "Key exported to identity_export.dat", 0, 0);
                else
                    tui_add_chat(&tui, "Export failed", 0, 0);
                tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
                goto done_input;
            }
            if (strcmp(tui.input_buf, "/backup") == 0 && tui.identity_ready) {
                char backup_path[512];
                snprintf(backup_path, sizeof(backup_path), "%s/identity_backup.dat", path);
                if (identity_backup(&id, backup_path, NULL) == 0)
                    tui_add_chat(&tui, "Backup saved to identity_backup.dat", 0, 0);
                else
                    tui_add_chat(&tui, "Backup failed", 0, 0);
                tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
                goto done_input;
            }
            if (strncmp(tui.input_buf, "/restore ", 9) == 0 && tui.identity_ready) {
                char restore_path[512];
                sscanf(tui.input_buf + 9, "%511s", restore_path);
                identity_t restored;
                if (identity_restore(&restored, restore_path, NULL) == 0) {
                    id = restored;
                    secure_store_set_key(id.identity_key, 32);
                    tui.identity = id;
                    snprintf(tui.username, sizeof(tui.username), "%s", id.username);
                    snprintf(tui.display_name, sizeof(tui.display_name), "%s", id.display_name);
                    tui_add_chat(&tui, "Identity restored from backup", 0, 0);
                } else {
                    tui_add_chat(&tui, "Restore failed", 0, 0);
                }
                tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
                goto done_input;
            }
            if (strcmp(tui.input_buf, "/known_hosts") == 0) {
                tui_add_chat(&tui, "Known hosts:", 0, 0);
                char kh_path[512];
                snprintf(kh_path, sizeof(kh_path), "%s", path);
                known_hosts_print(kh_path);
                tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
                goto done_input;
            }
            if (strncmp(tui.input_buf, "/room ", 6) == 0) {
                char cmd[32] = {0};
                char name[32] = {0};
                int n = sscanf(tui.input_buf + 6, "%31s %31s", cmd, name);
                if (n >= 1 && strcmp(cmd, "list") == 0) {
                    int rcount;
                    group_get_rooms(&rcount);
                    char msg[128];
                    snprintf(msg, sizeof(msg), "Rooms: %d total", rcount);
                    if (tui.screen == SCREEN_GROUP)
                        group_add_message(tui.current_room, "system", msg, 0);
                    else
                        tui_add_chat(&tui, msg, 0, 0);
                } else if (n >= 2 && strcmp(cmd, "create") == 0) {
                    if (group_create(name, "") == 0) {
                        snprintf(tui.current_room, sizeof(tui.current_room), "%s", name);
                        tui.screen = SCREEN_GROUP;
                        tui.group_focus = GROUP_FOCUS_CHAT;
                        char msg[128];
                        snprintf(msg, sizeof(msg), "Room #%s created", name);
                        group_add_message(name, "system", msg, 0);
                    } else {
                        tui_add_chat(&tui, "Room creation failed (may already exist)", 0, 0);
                    }
                } else if (n >= 2 && strcmp(cmd, "join") == 0) {
                    group_room_t* r = group_find(name);
                    if (r) {
                        snprintf(tui.current_room, sizeof(tui.current_room), "%s", name);
                        tui.screen = SCREEN_GROUP;
                        tui.group_focus = GROUP_FOCUS_CHAT;
                    } else {
                        tui_add_chat(&tui, "Room not found", 0, 0);
                    }
                } else if (n >= 2 && strcmp(cmd, "leave") == 0) {
                    group_room_t* r = group_find(name);
                    if (r) {
                        group_add_message(name, "system", "You left the room", 0);
                        if (strcmp(tui.current_room, name) == 0)
                            tui.current_room[0] = '\0';
                    }
                } else {
                    tui_add_chat(&tui, "Usage: /room <create|join|leave|list> [name]", 0, 0);
                }
                tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
                goto done_input;
            }
            if (strncmp(tui.input_buf, "/import ", 8) == 0 && tui.identity_ready) {
                char hex[65] = {0};
                if (sscanf(tui.input_buf + 8, "%64s", hex) == 1 && identity_import_key(&id, path, hex) == 0) {
                    tui.identity = id;
                    char fp[128];
                    identity_get_fingerprint(&id, fp, sizeof(fp));
                    tui_add_chat(&tui, "Key imported", 0, 0);
                    tui_add_chat(&tui, fp, 0, 0);
                } else {
                    tui_add_chat(&tui, "Usage: /import <64-char-hex-key>", 0, 0);
                }
                tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
                goto done_input;
            }
        }

        if (input == -10 && tui.screen == SCREEN_LOGIN) {
            identity_create(&id, path, tui.login_username,
                            tui.login_display[0] ? tui.login_display : tui.login_username);
            tui.identity = id;
            tui.identity_ready = 1;
            snprintf(tui.username, sizeof(tui.username), "%s", id.username);
            snprintf(tui.display_name, sizeof(tui.display_name), "%s", id.display_name);
            snprintf(tui.login_display, sizeof(tui.login_display), "%s", id.display_name);
            tui.screen = SCREEN_PEER_LIST;
            tui.dirty = 1;
            if (!g_transport_started)
                start_transport(&tui, argc, argv);
            tui_event_journal_add(&tui, "identity", "identity created");
        } else if (input == 1 && tui.screen == SCREEN_GROUP && tui.group_focus == GROUP_FOCUS_CHAT && tui.current_room[0]) {
            tui.input_buf[input] = '\0';
            group_add_message(tui.current_room, tui.username, tui.input_buf, 0);
            group_room_t* room = group_find(tui.current_room);
            if (room) {
                for (int i = 0; i < room->member_count; i++) {
                    group_member_t* m = &room->members[i];
                    for (int p = 0; p < tui.peer_count; p++) {
                        if (strcmp(tui.peers[p].addr, m->addr) == 0 &&
                            tui.peers[p].port == m->port &&
                            tui.peers[p].is_connected) {
                            transport_send_chat(tui.input_buf);
                            break;
                        }
                    }
                }
            }
            tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
        } else if (input == 1 && tui.conn_info.state == CONN_LOCKED) {
            tui.input_buf[input] = '\0';
            transport_send_chat(tui.input_buf);
            char line[1100];
            snprintf(line, sizeof(line), "%s", tui.input_buf);
            tui_add_chat(&tui, line, 0, 1);
            tui.input_len = 0; tui.input_pos = 0;
        } else if (input > 1 && input < 10) {
            tui.input_buf[input] = '\0';
            conn_info_t ci;
            transport_get_connection_info(&ci);
            if (ci.state == CONN_LOCKED) {
                transport_send_chat(tui.input_buf);
                char line[1100];
                snprintf(line, sizeof(line), "%s", tui.input_buf);
                tui_add_chat(&tui, line, 0, 1);
            } else {
                tui_add_chat(&tui, "Not connected yet", 0, 0);
            }
            tui.input_len = 0; tui.input_pos = 0;
        } else if (input >= 10) {
            int peer_idx = input - 10;
            if (peer_idx < tui.peer_count) {
                peer_entry_t* p = &tui.peers[peer_idx];
                if (!p->is_connected) {
                    transport_send_connect_request(p->addr, p->port, tui.username, tui.display_name);
                    tui.screen = SCREEN_CHAT;
                    snprintf(tui.chat_partner, sizeof(tui.chat_partner), "%s", p->username[0] ? p->username : p->addr);
                    tui_add_chat(&tui, "Connection request sent...", 0, 0);
                    tui.dirty = 1;
                } else {
                    tui.screen = SCREEN_CHAT;
                    snprintf(tui.chat_partner, sizeof(tui.chat_partner), "%s", p->username[0] ? p->username : p->addr);
                    tui.dirty = 1;
                }
                tui.unread_count = 0;
            }
        } else if (input == -4) {
            transport_accept_connection(tui.conn_req_addr, tui.conn_req_port);
            tui.screen = SCREEN_CHAT;
            snprintf(tui.chat_partner, sizeof(tui.chat_partner), "%s", tui.conn_req_username);
            tui_add_chat(&tui, "Connection accepted, handshake starting...", 0, 0);
            tui.unread_count = 0;
            tui.dirty = 1;
        } else if (input == -5) {
            transport_decline_connection(tui.conn_req_addr, tui.conn_req_port);
            tui.dirty = 1;
        } else if (input == -30) {
            transport_audio_call_start();
            tui.audio_active = 1;
            tui_add_chat(&tui, "\033[1;35m[Audio call accepted]\033[0m", 0, 0);
            tui.dirty = 1;
        } else if (input == -31) {
            tui_add_chat(&tui, "\033[1;35m[Audio call declined]\033[0m", 0, 0);
            tui.dirty = 1;
        } else if (input == -32) {
            transport_video_call_start();
            tui.video_active = 1;
            tui_add_chat(&tui, "\033[1;36m[Video call accepted]\033[0m", 0, 0);
            tui.dirty = 1;
        } else if (input == -33) {
            tui_add_chat(&tui, "\033[1;36m[Video call declined]\033[0m", 0, 0);
            tui.dirty = 1;
        } else if (input == -20) {
            if (tui.conn_info.state == CONN_LOCKED) {
                if (tui.audio_active) {
                    transport_audio_call_end();
                    tui.audio_active = 0;
                    tui_add_chat(&tui, "\033[1;35m[Audio call ended]\033[0m", 0, 0);
                } else {
                    transport_audio_call_start();
                    tui.audio_active = 1;
                    tui_add_chat(&tui, "\033[1;35m[Audio call started]\033[0m", 0, 0);
                }
                tui.dirty = 1;
            }
        } else if (input == -21) {
            if (tui.conn_info.state == CONN_LOCKED) {
                if (tui.video_active) {
                    transport_video_call_end();
                    tui.video_active = 0;
                    tui_add_chat(&tui, "\033[1;36m[Video call ended]\033[0m", 0, 0);
                } else {
                    transport_video_call_start();
                    tui.video_active = 1;
                    tui_add_chat(&tui, "\033[1;36m[Video call started]\033[0m", 0, 0);
                }
                tui.dirty = 1;
            }
        } else if (input == -22) {
            if (tui.conn_info.state == CONN_LOCKED && tui.input_len > 0) {
                tui.input_buf[tui.input_len] = '\0';
                if (transport_send_file(tui.input_buf) == 0) {
                    char msg[1100];
                    snprintf(msg, sizeof(msg), "\033[1;35m[Sending: %s]\033[0m", tui.input_buf);
                    tui_add_chat(&tui, msg, 0, 0);
                } else {
                    tui_add_chat(&tui, "\033[1;31m[File send failed]\033[0m", 0, 0);
                }
                tui.input_len = 0; tui.input_pos = 0; tui.dirty = 1;
            }
        } else if (input == -40) {
            /* Ctrl+S — open settings */
            tui.screen = SCREEN_SETTINGS;
            tui.settings_selection = 0;
            tui.dirty = 1;
        } else if (input == -41) {
            /* Ctrl+D — open advanced from settings */
            tui.screen = SCREEN_ADVANCED;
            tui.adv_tab = 0;
            tui.adv_paused = 0;
            tui.space = 1;
            tui.dirty = 1;
        } else if (input == -42) {
            /* F2 — return from advanced */
            tui.screen = SCREEN_PEER_LIST;
            tui.space = 0;
            tui.dirty = 1;
        }

done_input:
        tui_render(&tui);
        frame++;
    }

    monitor_stop();
    if (g_transport_started) transport_shutdown();
    tui_shutdown(&tui);
    return 0;
}

#ifndef _WIN32
static volatile int g_daemon_running = 1;

static void daemon_signal_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT) g_daemon_running = 0;
}

static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) {
        FILE* pf = fopen("/tmp/pqcommd.pid", "w");
        if (pf) { fprintf(pf, "%d\n", pid); fclose(pf); }
        printf("Daemon started, PID %d\n", pid);
        exit(0);
    }
    setsid();
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    close(0); close(1); close(2);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
    chdir("/tmp");
}

static int run_daemon(int argc, char** argv)
{
    openlog("pqcommd", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "pqcommd starting");

    identity_t id;
    const char* config_dir = getenv("HOME");
    char path[512];
    if (config_dir)
        snprintf(path, sizeof(path), "%s/.config/ssm", config_dir);
    else
        snprintf(path, sizeof(path), "/tmp/.config/ssm");

    int identity_ok = 0;
    if (identity_init(&id, path) == 0 && id.initialized) {
        identity_ok = 1;
        syslog(LOG_INFO, "loaded identity: %s", id.username);
    }
    if (!identity_ok) {
        syslog(LOG_ERR, "no identity found, run --tui first");
        return 1;
    }

    transport_config_t config;
    memset(&config, 0, sizeof(config));
    config.local_port = 9001;
    config.local_port_alt = 9003;
    config.discovery_port = 9009;
    config.discovery_enabled = 1;
    config.fec_enabled = 1;
    config.fec_group_size = 4;
    config.multipath_enabled = 0;
    config.path_count = 1;
    config.handshake_timeout_ms = 5000;
    config.heartbeat_interval_ms = 1000;
    config.reconnect_timeout_ms = 5000;
    config.max_reconnect_attempts = 3;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            config.local_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--discovery-port") == 0 && i + 1 < argc)
            config.discovery_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--no-discovery") == 0)
            config.discovery_enabled = 0;
    }

    if (transport_init(&config) != 0) {
        syslog(LOG_ERR, "transport_init failed");
        return 1;
    }
    lan_discovery_set_username(id.username);
    syslog(LOG_INFO, "transport initialized, port %d", config.local_port);

    signal(SIGTERM, daemon_signal_handler);
    signal(SIGINT, daemon_signal_handler);

    while (g_daemon_running) {
        transport_event_t ev;
        while (transport_poll_event(&ev) > 0) {
            if (ev.type == EVENT_CONNECT_REQUEST) {
                transport_accept_connection(ev.data.conn_req.addr, ev.data.conn_req.port);
                syslog(LOG_INFO, "auto-accepted connection from %s:%d (%s)",
                       ev.data.conn_req.addr, ev.data.conn_req.port, ev.data.conn_req.username);
            } else if (ev.type == EVENT_CHAT_RECEIVED) {
                syslog(LOG_INFO, "chat from %d: %s", ev.data.chat.sender_port, ev.data.chat.text);
            } else if (ev.type == EVENT_CONNECTION_STATE_CHANGED) {
                if (ev.data.conn_state.new_state == CONN_LOCKED)
                    syslog(LOG_INFO, "session locked (encrypted)");
            } else if (ev.type == EVENT_AUDIO_CALL_REQUEST) {
                syslog(LOG_INFO, "audio call from %s (auto-accept)", ev.data.call_req.peer_username);
                transport_audio_call_start();
            } else if (ev.type == EVENT_VIDEO_CALL_REQUEST) {
                syslog(LOG_INFO, "video call from %s (auto-decline)", ev.data.call_req.peer_username);
            } else if (ev.type == EVENT_FILE_TRANSFER_COMPLETE) {
                syslog(LOG_INFO, "file transfer complete");
            } else if (ev.type == EVENT_FILE_TRANSFER_FAILED) {
                syslog(LOG_WARNING, "file transfer failed");
            }
        }
        lan_discovery_trigger_scan();
        uint64_t now_ms = (uint64_t)time(NULL) * 1000;
        connection_manager_mark_stale(now_ms, 30000);
        usleep(200000);
    }

    syslog(LOG_INFO, "pqcommd shutting down");
    transport_shutdown();
    closelog();
    unlink("/tmp/pqcommd.pid");
    return 0;
}
#endif /* _WIN32 */

int main(int argc, char** argv)
{
    if (argc > 1 && strcmp(argv[1], "--tui") == 0)
        return run_tui(argc, argv);
#ifndef _WIN32
    if (argc > 1 && strcmp(argv[1], "--daemon") == 0) {
        if (argc > 2 && strcmp(argv[2], "--foreground") == 0)
            return run_daemon(argc, argv);
        daemonize();
        return run_daemon(argc, argv);
    }
#endif
    return transport_engine_run_demo();
}
