cmake_minimum_required(VERSION 3.20)

project(transport C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SRC
    main.c
    core/pool.c
    core/udp.c

    core/rx_thread.c
    core/tx_thread.c

    core/io_poll_win.c

    layers/packet_parse.c

    layers/offensive.c
    layers/anti_analysis.c
    layers/static_shell.c
    layers/kernel_filter_stub.c

    layers/session_gate.c
    layers/resilience.c
    layers/session_enc.c
    layers/channel_enc.c

    core/scheduler.c

    layers/seq_check.c

    layers/rx_demux.c

    pipeline/pipeline_inbound.c
    pipeline/pipeline_selftest.c

    core/rx_worker.c
)

if (WIN32)
    list(APPEND SRC
        core/udp_win.c
        core/io_wait_win.c
    )
else()
    list(APPEND SRC
        core/udp_posix.c
        core/io_wait_posix.c
    )
endif()

add_executable(transport ${SRC})

if (WIN32)
    target_link_libraries(transport ws2_32)
endif()

target_include_directories(transport PRIVATE
    core
    layers
    pipeline
)