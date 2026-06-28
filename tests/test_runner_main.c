#include <stdio.h>
#include <string.h>

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
    int ret = t->fn();
    printf("[%s] %s\n", ret == 0 ? "PASS" : "FAIL", t->name);
    return ret;
}

static int run_all_tests(void)
{
    int failed = 0;
    for (int i = 0; i < num_tests; i++)
        failed += (run_test(&all_tests[i]) != 0);
    printf("\n%d/%d tests passed\n", num_tests - failed, num_tests);
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
        int failed = 0;
        int found  = 0;
        for (int a = 1; a < argc; a++) {
            for (int i = 0; i < num_tests; i++) {
                if (strcmp(all_tests[i].name, argv[a]) == 0) {
                    found = 1;
                    failed += (run_test(&all_tests[i]) != 0);
                    break;
                }
            }
            if (!found) {
                printf("[SKIP] %s (not found)\n", argv[a]);
                found = 0;
            }
        }
        return failed;
    }
    return run_all_tests();
}
