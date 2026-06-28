#include "transport_engine.h"
#include "tui.h"
#include "tui_screen.h"
#include "tui_input.h"
#include "toml_config.h"
#include "identity.h"
#include "secure_store.h"
#include "lan_discovery.h"
#include "connection_manager.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>

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

static int run_tui(int argc, char** argv)
{
    tui_t tui;
    tui_init(&tui);
    tui_term_init(&tui);

    /* try loading existing identity */
    identity_t id;
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

    tui_render(&tui);
    int frame = 0;

    while (tui.running) {
        /* process transport events */
        if (g_transport_started) {
            transport_event_t ev;
            while (transport_poll_event(&ev) > 0) {
                if (ev.type == EVENT_CHAT_RECEIVED) {
                    tui_add_chat(&tui, ev.data.chat.text, ev.data.chat.sender_port, 0);
                    if (tui.screen != SCREEN_CHAT) tui.unread_count++;
                }
                else if (ev.type == EVENT_CONNECTION_STATE_CHANGED) {
                    if (ev.data.conn_state.new_state == CONN_LOCKED)
                        tui_add_chat(&tui, "Session locked (PQ encrypted)", 0, 0);
                } else if (ev.type == EVENT_CONNECT_REQUEST) {
                    tui.show_conn_popup = 1;
                    tui.conn_popup_selection = 0;
                    snprintf(tui.conn_req_addr, sizeof(tui.conn_req_addr), "%s", ev.data.conn_req.addr);
                    tui.conn_req_port = ev.data.conn_req.port;
                    snprintf(tui.conn_req_username, sizeof(tui.conn_req_username), "%s", ev.data.conn_req.username);
                    snprintf(tui.conn_req_display, sizeof(tui.conn_req_display), "%s", ev.data.conn_req.display_name);
                    tui.dirty = 1;
                } else if (ev.type == EVENT_CONNECT_ACCEPTED) {
                    transport_connect(ev.data.conn_req.addr, ev.data.conn_req.port);
                    tui.screen = SCREEN_CHAT;
                    snprintf(tui.chat_partner, sizeof(tui.chat_partner), "%s", ev.data.conn_req.username);
                    tui_add_chat(&tui, "Connecting...", 0, 0);
                    tui.dirty = 1;
                } else if (ev.type == EVENT_CONNECT_DECLINED) {
                    tui_add_chat(&tui, "Connection declined", 0, 0);
                    tui.dirty = 1;
                } else if (ev.type == EVENT_AUDIO_CALL_REQUEST) {
                    tui.show_call_popup = 1;
                    tui.call_popup_type = 0;
                    tui.call_popup_selection = 0;
                    snprintf(tui.call_req_peer, sizeof(tui.call_req_peer), "%s", ev.data.call_req.peer_username);
                    tui.dirty = 1;
                } else if (ev.type == EVENT_VIDEO_CALL_REQUEST) {
                    tui.show_call_popup = 1;
                    tui.call_popup_type = 1;
                    tui.call_popup_selection = 0;
                    snprintf(tui.call_req_peer, sizeof(tui.call_req_peer), "%s", ev.data.call_req.peer_username);
                    tui.dirty = 1;
                } else if (ev.type == EVENT_AUDIO_CALL_ACCEPTED) {
                    tui_add_chat(&tui, "\033[1;35m[Audio call connected]\033[0m", 0, 0);
                    tui.audio_active = 1;
                    tui.dirty = 1;
                } else if (ev.type == EVENT_AUDIO_CALL_ENDED) {
                    tui_add_chat(&tui, "\033[1;35m[Audio call ended]\033[0m", 0, 0);
                    tui.audio_active = 0;
                    tui.dirty = 1;
                } else if (ev.type == EVENT_VIDEO_CALL_ACCEPTED) {
                    tui_add_chat(&tui, "\033[1;36m[Video call connected]\033[0m", 0, 0);
                    tui.video_active = 1;
                    tui.dirty = 1;
                } else if (ev.type == EVENT_VIDEO_CALL_ENDED) {
                    tui_add_chat(&tui, "\033[1;36m[Video call ended]\033[0m", 0, 0);
                    tui.video_active = 0;
                    tui.dirty = 1;
                } else if (ev.type == EVENT_FILE_TRANSFER_COMPLETE) {
                    tui_add_chat(&tui, "\033[1;32m[File transfer complete]\033[0m", 0, 0);
                    tui.dirty = 1;
                } else if (ev.type == EVENT_FILE_TRANSFER_FAILED) {
                    tui_add_chat(&tui, "\033[1;31m[File transfer failed]\033[0m", 0, 0);
                    tui.dirty = 1;
                } else if (ev.type == EVENT_FILE_TRANSFER_PROGRESS) {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "\033[1;33m[File: %s %u/%u]\033[0m",
                             ev.data.file.filename, ev.data.file.progress, ev.data.file.total_size);
                    tui_add_chat(&tui, msg, 0, 0);
                    tui.dirty = 1;
                } else if (ev.type == EVENT_TYPING) {
                    if (tui.chat_partner[0]) {
                        snprintf(tui.typing_peer, sizeof(tui.typing_peer), "%s", tui.chat_partner);
                        tui.typing_tick = 4; /* show for ~4 frames (~800ms) */
                        tui.dirty = 1;
                    }
                } else if (ev.type == EVENT_DELIVERY_ACK) {
                    /* mark newest undelivered self-message as delivered */
                    for (int i = tui.chat_count - 1; i >= 0; i--) {
                        if (tui.chat_lines[i].is_self && tui.chat_lines[i].status == 0) {
                            tui.chat_lines[i].status = 1;
                            break;
                        }
                    }
                    tui.dirty = 1;
                } else if (ev.type == EVENT_READ_ACK) {
                    /* mark newest delivered self-message as read */
                    for (int i = tui.chat_count - 1; i >= 0; i--) {
                        if (tui.chat_lines[i].is_self && tui.chat_lines[i].status == 1) {
                            tui.chat_lines[i].status = 2;
                            break;
                        }
                    }
                    tui.dirty = 1;
                }
            }
        }

        /* send typing indicator if flag set */
        if (tui.typing_flag && tui.conn_info.state == CONN_LOCKED) {
            transport_send_typing();
            tui.typing_flag = 0;
        }

        /* decrement typing display timer */
        if (tui.typing_tick > 0) {
            tui.typing_tick--;
            if (tui.typing_tick == 0) tui.dirty = 1;
        }

        conn_info_t info;
        transport_get_connection_info(&info);
        tui_update_info(&tui, &info);

        /* update peer list periodically + discovery + stale marking */
        if (g_transport_started && frame % 10 == 0) {
            lan_discovery_trigger_scan();
            uint64_t now_ms = (uint64_t)time(NULL) * 1000;
            connection_manager_mark_stale(now_ms, 30000); /* 30s timeout */

            peer_entry_t peers[32];
            int n = transport_get_peer_list(peers, 32);
            if (n != tui.peer_count || (n > 0 && memcmp(tui.peers, peers, (size_t)n * sizeof(peer_entry_t)) != 0)) {
                tui.peer_count = n;
                if (n > 0) memcpy(tui.peers, peers, (size_t)n * sizeof(peer_entry_t));
                tui.dirty = 1;
            }
        }

        /* poll input */
        int input = tui_input_poll(&tui, 200);
        if (input >= 1 && tui.input_len > 0) {
            tui.input_buf[tui.input_len] = '\0';
            if (strncmp(tui.input_buf, "/connect ", 9) == 0) {
                char ip[64] = {0};
                int port = 0;
                if (sscanf(tui.input_buf + 9, "%63s %d", ip, &port) == 2 && port > 0 && port < 65536) {
                    transport_send_connect_request(ip, (uint16_t)port,
                                                    tui.username, tui.display_name);
                    tui.screen = SCREEN_CHAT;
                    snprintf(tui.chat_partner, sizeof(tui.chat_partner), "%s:%d", ip, port);
                    tui_add_chat(&tui, "Connection request sent...", 0, 0);
                } else {
                    tui_add_chat(&tui, "Usage: /connect <ip> <port>", 0, 0);
                }
                tui.input_len = 0;
                tui.input_pos = 0;
                tui.dirty = 1;
                goto done_input;
            }
            if (strcmp(tui.input_buf, "/fingerprint") == 0 && tui.identity_ready) {
                char fp[128];
                identity_get_fingerprint(&id, fp, sizeof(fp));
                tui_add_chat(&tui, fp, 0, 0);
                tui.input_len = 0;
                tui.input_pos = 0;
                tui.dirty = 1;
                goto done_input;
            }
            if (strcmp(tui.input_buf, "/mykey") == 0 && tui.identity_ready) {
                char keyhex[128];
                identity_get_key_hex(&id, keyhex, sizeof(keyhex));
                tui_add_chat(&tui, keyhex, 0, 0);
                tui.input_len = 0;
                tui.input_pos = 0;
                tui.dirty = 1;
                goto done_input;
            }
            if (strcmp(tui.input_buf, "/export") == 0 && tui.identity_ready) {
                char export_path[512];
                snprintf(export_path, sizeof(export_path), "%s/identity_export.dat", path);
                if (identity_export_key(&id, export_path) == 0) {
                    tui_add_chat(&tui, "Key exported to identity_export.dat", 0, 0);
                } else {
                    tui_add_chat(&tui, "Export failed", 0, 0);
                }
                tui.input_len = 0;
                tui.input_pos = 0;
                tui.dirty = 1;
                goto done_input;
            }
            if (strcmp(tui.input_buf, "/backup") == 0 && tui.identity_ready) {
                char backup_path[512];
                snprintf(backup_path, sizeof(backup_path), "%s/identity_backup.dat", path);
                if (identity_backup(&id, backup_path, NULL) == 0) {
                    tui_add_chat(&tui, "Backup saved to identity_backup.dat", 0, 0);
                } else {
                    tui_add_chat(&tui, "Backup failed", 0, 0);
                }
                tui.input_len = 0;
                tui.input_pos = 0;
                tui.dirty = 1;
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
                tui.input_len = 0;
                tui.input_pos = 0;
                tui.dirty = 1;
                goto done_input;
            }
            if (strcmp(tui.input_buf, "/known_hosts") == 0) {
                tui_add_chat(&tui, "Known hosts:", 0, 0);
                char kh_path[512];
                snprintf(kh_path, sizeof(kh_path), "%s", path);
                known_hosts_print(kh_path);
                tui.input_len = 0;
                tui.input_pos = 0;
                tui.dirty = 1;
                goto done_input;
            }
            if (strncmp(tui.input_buf, "/import ", 8) == 0 && tui.identity_ready) {
                char hex[65] = {0};
                if (sscanf(tui.input_buf + 8, "%64s", hex) == 1 &&
                    identity_import_key(&id, path, hex) == 0)
                {
                    tui.identity = id; /* sync TUI copy */
                    char fp[128];
                    identity_get_fingerprint(&id, fp, sizeof(fp));
                    tui_add_chat(&tui, "Key imported", 0, 0);
                    tui_add_chat(&tui, fp, 0, 0);
                } else {
                    tui_add_chat(&tui, "Usage: /import <64-char-hex-key>", 0, 0);
                }
                tui.input_len = 0;
                tui.input_pos = 0;
                tui.dirty = 1;
                goto done_input;
            }
        }
        if (input == -10 && tui.screen == SCREEN_LOGIN) {
            /* login submitted */
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
        } else if (input == 1 && tui.conn_info.state == CONN_LOCKED) {
            /* Enter pressed in chat with non-empty input — send chat */
            tui.input_buf[input] = '\0';
            transport_send_chat(tui.input_buf);
            char line[1100];
            snprintf(line, sizeof(line), "%s", tui.input_buf);
            tui_add_chat(&tui, line, 0, 1);
            tui.input_len = 0;
            tui.input_pos = 0;
        } else if (input > 1 && input < 10) {
            /* chat submit */
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
            tui.input_len = 0;
            tui.input_pos = 0;
        } else if (input >= 10) {
            /* peer selected */
            int peer_idx = input - 10;
            if (peer_idx < tui.peer_count) {
                peer_entry_t* p = &tui.peers[peer_idx];
                if (!p->is_connected) {
                    transport_send_connect_request(p->addr, p->port,
                                                    tui.username, tui.display_name);
                    tui.screen = SCREEN_CHAT;
                    snprintf(tui.chat_partner, sizeof(tui.chat_partner), "%s", p->username[0] ? p->username : p->addr);
                    tui_add_chat(&tui, "Connection request sent...", 0, 0);
                    tui.dirty = 1;
                } else {
                    tui.screen = SCREEN_CHAT;
                    snprintf(tui.chat_partner, sizeof(tui.chat_partner), "%s", p->username[0] ? p->username : p->addr);
                    tui.dirty = 1;
                }
                tui.unread_count = 0; /* clear unread when entering chat */
            }
        }
        if (input == -4) {
            /* popup accept */
            transport_accept_connection(tui.conn_req_addr, tui.conn_req_port);
            tui.screen = SCREEN_CHAT;
            snprintf(tui.chat_partner, sizeof(tui.chat_partner), "%s", tui.conn_req_username);
            tui_add_chat(&tui, "Connection accepted, handshake starting...", 0, 0);
            tui.unread_count = 0;
            tui.dirty = 1;
        }
        if (input == -5) {
            /* popup decline */
            transport_decline_connection(tui.conn_req_addr, tui.conn_req_port);
            tui.dirty = 1;
        }
        if (input == -30) {
            /* audio call accept */
            transport_audio_call_start();
            tui.audio_active = 1;
            tui_add_chat(&tui, "\033[1;35m[Audio call accepted]\033[0m", 0, 0);
            tui.dirty = 1;
        }
        if (input == -31) {
            /* audio call decline */
            tui_add_chat(&tui, "\033[1;35m[Audio call declined]\033[0m", 0, 0);
            tui.dirty = 1;
        }
        if (input == -32) {
            /* video call accept */
            transport_video_call_start();
            tui.video_active = 1;
            tui_add_chat(&tui, "\033[1;36m[Video call accepted]\033[0m", 0, 0);
            tui.dirty = 1;
        }
        if (input == -33) {
            /* video call decline */
            tui_add_chat(&tui, "\033[1;36m[Video call declined]\033[0m", 0, 0);
            tui.dirty = 1;
        }
        if (input == -20) {
            /* Ctrl+A — audio call toggle */
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
        }
        if (input == -21) {
            /* Ctrl+V — video call toggle */
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
        }
        if (input == -22) {
            /* Ctrl+F — send file */
            if (tui.conn_info.state == CONN_LOCKED && tui.input_len > 0) {
                tui.input_buf[tui.input_len] = '\0';
                if (transport_send_file(tui.input_buf) == 0) {
                    char msg[1100];
                    snprintf(msg, sizeof(msg), "\033[1;35m[Sending: %s]\033[0m", tui.input_buf);
                    tui_add_chat(&tui, msg, 0, 0);
                } else {
                    tui_add_chat(&tui, "\033[1;31m[File send failed]\033[0m", 0, 0);
                }
                tui.input_len = 0;
                tui.input_pos = 0;
                tui.dirty = 1;
            }
        }

done_input:
        tui_render(&tui);
        frame++;
    }

    if (g_transport_started) transport_shutdown();
    tui_shutdown(&tui);
    return 0;
}

/* ================================================================
 * Daemon mode — headless background operation
 * ================================================================ */

static volatile int g_daemon_running = 1;

static void daemon_signal_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT) {
        g_daemon_running = 0;
    }
}

static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) {
        /* Write PID file */
        FILE* pf = fopen("/tmp/pqcommd.pid", "w");
        if (pf) { fprintf(pf, "%d\n", pid); fclose(pf); }
        printf("Daemon started, PID %d\n", pid);
        exit(0);
    }
    /* Child continues */
    setsid();
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Close stdin/stdout/stderr and reopen to /dev/null */
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

    /* Set up identity */
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

    /* Start transport */
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

    /* Signal handling */
    signal(SIGTERM, daemon_signal_handler);
    signal(SIGINT, daemon_signal_handler);

    /* Headless event loop */
    while (g_daemon_running) {
        transport_event_t ev;
        while (transport_poll_event(&ev) > 0) {
            if (ev.type == EVENT_CONNECT_REQUEST) {
                /* Auto-accept in daemon mode */
                transport_accept_connection(ev.data.conn_req.addr,
                                            ev.data.conn_req.port);
                syslog(LOG_INFO, "auto-accepted connection from %s:%d (%s)",
                       ev.data.conn_req.addr, ev.data.conn_req.port,
                       ev.data.conn_req.username);
            } else if (ev.type == EVENT_CHAT_RECEIVED) {
                syslog(LOG_INFO, "chat from %d: %s",
                       ev.data.chat.sender_port, ev.data.chat.text);
            } else if (ev.type == EVENT_CONNECTION_STATE_CHANGED) {
                if (ev.data.conn_state.new_state == CONN_LOCKED)
                    syslog(LOG_INFO, "session locked (encrypted)");
            } else if (ev.type == EVENT_AUDIO_CALL_REQUEST) {
                syslog(LOG_INFO, "audio call from %s (auto-accept)",
                       ev.data.call_req.peer_username);
                transport_audio_call_start();
            } else if (ev.type == EVENT_VIDEO_CALL_REQUEST) {
                syslog(LOG_INFO, "video call from %s (auto-decline)",
                       ev.data.call_req.peer_username);
            } else if (ev.type == EVENT_FILE_TRANSFER_COMPLETE) {
                syslog(LOG_INFO, "file transfer complete");
            } else if (ev.type == EVENT_FILE_TRANSFER_FAILED) {
                syslog(LOG_WARNING, "file transfer failed");
            }
        }

        /* Listen for connections */
        lan_discovery_trigger_scan();
        uint64_t now_ms = (uint64_t)time(NULL) * 1000;
        connection_manager_mark_stale(now_ms, 30000);

        usleep(200000); /* 200ms sleep */
    }

    syslog(LOG_INFO, "pqcommd shutting down");
    transport_shutdown();
    closelog();

    /* Remove PID file */
    unlink("/tmp/pqcommd.pid");

    return 0;
}

int main(int argc, char** argv)
{
    if (argc > 1 && strcmp(argv[1], "--tui") == 0)
        return run_tui(argc, argv);

    if (argc > 1 && strcmp(argv[1], "--daemon") == 0) {
        if (argc > 2 && strcmp(argv[2], "--foreground") == 0) {
            return run_daemon(argc, argv);
        }
        daemonize();
        return run_daemon(argc, argv);
    }

    return transport_engine_run_demo();
}
