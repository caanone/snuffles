cmake_minimum_required(VERSION 3.15)
project(snuffles C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
add_compile_options(-Wall -Wextra -O2)

if(APPLE)
    add_compile_definitions(_DARWIN_C_SOURCE)
elseif(UNIX)
    add_compile_definitions(_POSIX_C_SOURCE=200809L)
endif()

if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0601)
endif()

# Options
option(STATIC_LINK "Produce a single binary with static libpcap" OFF)
option(NO_PCAP "Build with raw sockets instead of libpcap (no Npcap needed on Windows)" OFF)

# Find dependencies
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(Threads REQUIRED)

# Common sources (everything except capture backend)
set(COMMON_SOURCES
    src/main.c
    src/dissect.c
    src/filter.c
    src/ringbuf.c
    src/ui.c
    src/export_pcap.c
    src/export_json.c
    src/stats.c
    src/session.c
    src/syslog_out.c
)

if(NO_PCAP)
    # ── Raw socket build (no libpcap) ──
    set(SOURCES ${COMMON_SOURCES} src/capture_raw.c)
    add_executable(${PROJECT_NAME} ${SOURCES})
    target_compile_definitions(${PROJECT_NAME} PRIVATE NO_PCAP)
    target_include_directories(${PROJECT_NAME} PRIVATE include)
    target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads m)
    if(WIN32)
        target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 iphlpapi)
    endif()
else()
    # ── libpcap build (default) ──
    find_package(PCAP REQUIRED)
    set(SOURCES ${COMMON_SOURCES} src/capture.c)
    add_executable(${PROJECT_NAME} ${SOURCES})
    target_include_directories(${PROJECT_NAME} PRIVATE include)
    target_link_libraries(${PROJECT_NAME} PRIVATE PCAP::PCAP Threads::Threads m)
    if(WIN32)
        target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)
    endif()
    if(STATIC_LINK)
        set_target_properties(${PROJECT_NAME} PROPERTIES LINK_SEARCH_START_STATIC ON)
        set_target_properties(${PROJECT_NAME} PROPERTIES LINK_SEARCH_END_STATIC ON)
        target_link_options(${PROJECT_NAME} PRIVATE -static)
    endif()
endif()

# Install
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
