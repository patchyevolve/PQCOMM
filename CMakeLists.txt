cmake_minimum_required(VERSION 3.20)

project(transport C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(MbedTLS CONFIG REQUIRED)
find_package(liboqs CONFIG REQUIRED)

# ============================================================
# libtransport.a — static library
# ============================================================

set(LIB_SRC
    lib/api/transport_api.c
    lib/engine/transport_engine.c
    lib/engine/heartbeat.c
    lib/engine/reconnect.c
    lib/connection/connection_manager.c
    lib/discovery/lan_discovery.c
    lib/core/pool.c
    lib/core/udp.c
    lib/core/session.c
    lib/core/rx_thread.c
    lib/core/tx_thread.c
    lib/core/scheduler.c
    lib/core/resilience_ctx.c
    lib/core/rx_worker.c
    lib/core/io_poll_win.c
    lib/layers/packet_parse.c
    lib/layers/offensive.c
    lib/layers/anti_analysis.c
    lib/layers/static_shell.c
    lib/layers/kernel_filter_stub.c
    lib/layers/session_gate.c
    lib/layers/resilience.c
    lib/layers/port_hop.c
    lib/layers/session_enc.c
    lib/layers/channel_enc.c
    lib/layers/seq_check.c
    lib/layers/rx_demux.c
    lib/pipeline/pipeline_inbound.c
    lib/pipeline/pipeline_selftest.c
    lib/crypto/kem.c
    lib/crypto/hkdf.c
    lib/crypto/aead.c
    lib/handshake/handshake.c
)

if (WIN32)
    list(APPEND LIB_SRC
        lib/core/udp_win.c
        lib/core/io_wait_win.c
    )
else()
    list(APPEND LIB_SRC
        lib/core/udp_posix.c
        lib/core/io_wait_posix.c
    )
endif()

add_library(transport_core STATIC ${LIB_SRC})

if (NOT WIN32)
    find_package(Threads REQUIRED)
endif()

target_link_libraries(transport_core PUBLIC
    MbedTLS::mbedtls
    MbedTLS::mbedcrypto
    MbedTLS::mbedx509
    OQS::oqs
    $<$<BOOL:${WIN32}>:ws2_32>
    $<$<NOT:$<BOOL:${WIN32}>>:Threads::Threads>
)

target_include_directories(transport_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/api>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/core>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/crypto>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/handshake>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/layers>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/pipeline>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/engine>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/connection>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/discovery>
)

# ============================================================
# transport — TUI executable
# ============================================================

add_executable(transport app/main.c)

target_link_libraries(transport PRIVATE transport_core)

target_include_directories(transport PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/app
)

# ============================================================
# test_runner — Test executable
# ============================================================

add_executable(test_runner
    tests/test_runner_main.c
    tests/test_connect.c
    tests/test_fec_loss.c
    tests/test_reconnect.c
    tests/test_port_hop.c
    tests/test_multipath_failover.c
    tests/test_helpers.c
)

target_link_libraries(test_runner PRIVATE transport_core)

target_include_directories(test_runner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
)
