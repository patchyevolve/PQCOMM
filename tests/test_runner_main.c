#include <stdio.h>
#include <string.h>

/* Test return code convention:
 *   0       = PASS
 *   TEST_SKIP = SKIP (test skipped, not a failure)
 *   other   = FAIL
 */
#define TEST_SKIP 42

extern int test_fec_recovery(void);
extern int test_fec_no_recovery_all_present(void);
extern int test_route_table_add_find(void);
extern int test_route_table_remove(void);
extern int test_route_table_update_metrics(void);
extern int test_abr_off(void);
extern int test_abr_low_loss(void);
extern int test_abr_high_loss(void);
extern int test_path_loss_window(void);
extern int test_path_state_transition(void);
extern int test_path_select(void);
extern int test_kf_whitelist(void);
extern int test_kf_blocklist(void);
extern int test_kf_size(void);
extern int test_kf_port(void);
extern int test_kf_bpf_map(void);
extern int test_kf_bpf_load(void);
extern int test_kf_bpf_attach_detach(void);
extern int test_kf_bpf_integration(void);
extern int test_aa_clean_packet(void);
extern int test_aa_bad_packet_scoring(void);
extern int test_off_trusted_bypass(void);
extern int test_off_repeated_unknown(void);
extern int test_audio_encode_decode(void);
extern int test_connect_basic(void);
extern int test_session_lifecycle(void);
extern int test_rekey_protocol(void);
extern int test_pool_basic(void);
extern int test_jitter_basic(void);
extern int test_identity_exchange_full(void);
extern int test_identity_bad_signature_rejected(void);

/* LAN integration tests */
extern int test_lan_full_handshake(void);
extern int test_lan_encrypted_chat(void);
extern int test_lan_rekey(void);
extern int test_lan_delivery_protocol(void);
extern int test_lan_audio_control(void);
extern int test_lan_mismatched_identity(void);

/* Fuzz tests */
extern int test_fuzz_handshake_corruption(void);
extern int test_fuzz_aead_corruption(void);
extern int test_fuzz_pipeline_corruption(void);
extern int test_fuzz_hkdf_random(void);
extern int test_fuzz_pool_alloc_stress(void);
extern int test_fuzz_session_enc_edge(void);

/* Load/stress tests */
extern int test_load_bulk_chat_messages(void);
extern int test_load_multi_session_concurrent(void);
extern int test_load_random_delay_handshake(void);
extern int test_load_reconnect_cycle(void);

/* Property-based tests */
extern int test_property_session_key_agreement(void);
extern int test_property_aead_roundtrip(void);
extern int test_property_hkdf_deterministic(void);
extern int test_property_session_state_machine(void);
extern int test_property_identity_key_exchange(void);

/* Group chat */
extern int test_group_create_wrapper(void);
extern int test_group_members_wrapper(void);
extern int test_group_messages_wrapper(void);
extern int test_group_list_wrapper(void);
extern int test_group_capacity_wrapper(void);
extern int test_group_msg_rollover_wrapper(void);

/* Benchmarks */
extern int test_bench_handshake_latency(void);
extern int test_bench_chat_throughput(void);
extern int test_bench_aead_encrypt(void);
extern int test_bench_aead_decrypt(void);
extern int test_bench_hkdf_derive(void);
extern int test_bench_kem_keypair(void);
extern int test_bench_kem_encaps(void);

typedef struct {
    const char* name;
    int (*fn)(void);
} test_entry_t;

static test_entry_t all_tests[] = {
    {"test_fec_recovery",              test_fec_recovery},
    {"test_fec_no_recovery_all_present", test_fec_no_recovery_all_present},
    {"test_route_table_add_find",      test_route_table_add_find},
    {"test_route_table_remove",        test_route_table_remove},
    {"test_route_table_update_metrics", test_route_table_update_metrics},
    {"test_abr_off",                   test_abr_off},
    {"test_abr_low_loss",              test_abr_low_loss},
    {"test_abr_high_loss",             test_abr_high_loss},
    {"test_path_loss_window",          test_path_loss_window},
    {"test_path_state_transition",     test_path_state_transition},
    {"test_path_select",               test_path_select},
    {"test_kf_whitelist",              test_kf_whitelist},
    {"test_kf_blocklist",              test_kf_blocklist},
    {"test_kf_size",                   test_kf_size},
    {"test_kf_port",                   test_kf_port},
    {"test_kf_bpf_map",                test_kf_bpf_map},
    {"test_kf_bpf_load",               test_kf_bpf_load},
    {"test_kf_bpf_attach_detach",      test_kf_bpf_attach_detach},
    {"test_kf_bpf_integration",        test_kf_bpf_integration},
    {"test_aa_clean_packet",           test_aa_clean_packet},
    {"test_aa_bad_packet_scoring",     test_aa_bad_packet_scoring},
    {"test_off_trusted_bypass",        test_off_trusted_bypass},
    {"test_off_repeated_unknown",      test_off_repeated_unknown},
    {"test_audio_encode_decode",       test_audio_encode_decode},
    {"test_connect_basic",             test_connect_basic},
    {"test_session_lifecycle",         test_session_lifecycle},
    {"test_rekey_protocol",            test_rekey_protocol},
    {"test_pool_basic",                test_pool_basic},
    {"test_jitter_basic",              test_jitter_basic},
    {"test_identity_exchange_full",    test_identity_exchange_full},
    {"test_identity_bad_signature_rejected", test_identity_bad_signature_rejected},

    /* LAN integration */
    {"test_lan_full_handshake",            test_lan_full_handshake},
    {"test_lan_encrypted_chat",            test_lan_encrypted_chat},
    {"test_lan_rekey",                     test_lan_rekey},
    {"test_lan_delivery_protocol",         test_lan_delivery_protocol},
    {"test_lan_audio_control",             test_lan_audio_control},
    {"test_lan_mismatched_identity",       test_lan_mismatched_identity},

    /* Fuzz */
    {"test_fuzz_handshake_corruption",     test_fuzz_handshake_corruption},
    {"test_fuzz_aead_corruption",          test_fuzz_aead_corruption},
    {"test_fuzz_pipeline_corruption",      test_fuzz_pipeline_corruption},
    {"test_fuzz_hkdf_random",              test_fuzz_hkdf_random},
    {"test_fuzz_pool_alloc_stress",        test_fuzz_pool_alloc_stress},
    {"test_fuzz_session_enc_edge",         test_fuzz_session_enc_edge},

    /* Load */
    {"test_load_bulk_chat_messages",       test_load_bulk_chat_messages},
    {"test_load_multi_session_concurrent", test_load_multi_session_concurrent},
    {"test_load_random_delay_handshake",   test_load_random_delay_handshake},
    {"test_load_reconnect_cycle",          test_load_reconnect_cycle},

    /* Property */
    {"test_property_session_key_agreement",    test_property_session_key_agreement},
    {"test_property_aead_roundtrip",           test_property_aead_roundtrip},
    {"test_property_hkdf_deterministic",       test_property_hkdf_deterministic},
    {"test_property_session_state_machine",    test_property_session_state_machine},
    {"test_property_identity_key_exchange",    test_property_identity_key_exchange},

    /* Group */
    {"test_group_create",              test_group_create_wrapper},
    {"test_group_members",             test_group_members_wrapper},
    {"test_group_messages",            test_group_messages_wrapper},
    {"test_group_list",                test_group_list_wrapper},
    {"test_group_capacity",            test_group_capacity_wrapper},
    {"test_group_msg_rollover",        test_group_msg_rollover_wrapper},

    /* Benchmarks */
    {"test_bench_handshake_latency",    test_bench_handshake_latency},
    {"test_bench_chat_throughput",      test_bench_chat_throughput},
    {"test_bench_aead_encrypt",         test_bench_aead_encrypt},
    {"test_bench_aead_decrypt",         test_bench_aead_decrypt},
    {"test_bench_hkdf_derive",          test_bench_hkdf_derive},
    {"test_bench_kem_keypair",          test_bench_kem_keypair},
    {"test_bench_kem_encaps",           test_bench_kem_encaps},
};
static const int num_tests = sizeof(all_tests) / sizeof(all_tests[0]);

static int run_test(test_entry_t* t)
{
    return t->fn();
}

static void print_verdict(const char* name, int ret)
{
    const char* verdict = "FAIL";
    if (ret == 0)         verdict = "PASS";
    else if (ret == TEST_SKIP) verdict = "SKIP";
    printf("[%s] %s\n", verdict, name);
}

static int run_all_tests(void)
{
    int passed = 0, skipped = 0, failed = 0;
    for (int i = 0; i < num_tests; i++) {
        int ret = run_test(&all_tests[i]);
        print_verdict(all_tests[i].name, ret);
        if (ret == 0)            passed++;
        else if (ret == TEST_SKIP) skipped++;
        else                     failed++;
    }
    printf("\n%d/%d tests passed (%d skipped, %d failed)\n",
           passed, num_tests, skipped, failed);
    return failed;
}

int main(int argc, char** argv)
{
    if (argc > 1 && strcmp(argv[1], "--list") == 0) {
        printf("Available tests:\n");
        for (int i = 0; i < num_tests; i++)
            printf("  %s\n", all_tests[i].name);
        return 0;
    }
    if (argc > 1) {
        int failed = 0, skipped = 0, passed = 0;
        for (int a = 1; a < argc; a++) {
            int found = 0;
            for (int i = 0; i < num_tests; i++) {
                if (strcmp(all_tests[i].name, argv[a]) == 0) {
                    int ret = run_test(&all_tests[i]);
                    print_verdict(all_tests[i].name, ret);
                    if (ret == 0)            passed++;
                    else if (ret == TEST_SKIP) skipped++;
                    else                     failed++;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                printf("[SKIP] %s (not found)\n", argv[a]);
                skipped++;
            }
        }
        printf("\n%d/%d tests passed (%d skipped, %d failed)\n",
               passed, passed + skipped + failed, skipped, failed);
        return failed;
    }
    return run_all_tests();
}
