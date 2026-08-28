cmake_minimum_required(VERSION 3.15)
project(snuffles VERSION 1.3.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Compiler flags (optimization comes from CMAKE_BUILD_TYPE)
add_compile_options(-Wall -Wextra)

if(APPLE)
    add_compile_definitions(_DARWIN_C_SOURCE)
elseif(UNIX)
    # _DEFAULT_SOURCE: glibc hides struct ifreq/SO_BINDTODEVICE/IFF_PROMISC
    # behind it when strict _POSIX_C_SOURCE is defined.
    add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)
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
    src/config.c
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
    set(SOURCES ${COMMON_SOURCES} src/capture_raw.c src/cbpf.c src/rawring.c)
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

# Tests (backend-independent: each links only the sources it exercises)
include(CTest)
if(BUILD_TESTING)
    foreach(t filter ringbuf session dissect cbpf rawring config syslog_out)
        add_executable(test_${t} tests/test_${t}.c src/${t}.c)
        target_include_directories(test_${t} PRIVATE include src)
        target_link_libraries(test_${t} PRIVATE Threads::Threads m)
        add_test(NAME ${t} COMMAND test_${t})
    endforeach()
    # export_json.c also walks the ring through the display filter
    add_executable(test_export_json tests/test_export_json.c src/export_json.c
                   src/filter.c src/ringbuf.c)
    target_include_directories(test_export_json PRIVATE include src)
    target_link_libraries(test_export_json PRIVATE Threads::Threads m)
    add_test(NAME export_json COMMAND test_export_json)
endif()

# Install
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
install(FILES docs/snuffles.1 DESTINATION share/man/man1)
