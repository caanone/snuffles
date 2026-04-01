# FindPCAP.cmake - Find libpcap / Npcap
#
# Creates imported target PCAP::PCAP
#
# Result variables:
#   PCAP_FOUND        - True if libpcap was found
#   PCAP_INCLUDE_DIRS - Include directories
#   PCAP_LIBRARIES    - Libraries to link

if(WIN32)
    # Npcap SDK: user must set NPCAP_SDK_DIR
    if(NOT NPCAP_SDK_DIR)
        set(NPCAP_SDK_DIR "C:/npcap-sdk" CACHE PATH "Path to Npcap SDK")
    endif()
    find_path(PCAP_INCLUDE_DIR pcap.h
        HINTS "${NPCAP_SDK_DIR}/Include"
    )
    find_library(PCAP_LIBRARY
        NAMES wpcap
        HINTS "${NPCAP_SDK_DIR}/Lib" "${NPCAP_SDK_DIR}/Lib/x64"
    )
    find_library(PACKET_LIBRARY
        NAMES Packet
        HINTS "${NPCAP_SDK_DIR}/Lib" "${NPCAP_SDK_DIR}/Lib/x64"
    )
else()
    # Unix: try pcap-config first, then pkg-config, then manual search
    find_program(PCAP_CONFIG pcap-config)
    if(PCAP_CONFIG)
        execute_process(COMMAND ${PCAP_CONFIG} --cflags
            OUTPUT_VARIABLE PCAP_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
        execute_process(COMMAND ${PCAP_CONFIG} --libs
            OUTPUT_VARIABLE PCAP_LDFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
        string(REGEX REPLACE "-I" "" PCAP_INCLUDE_DIR "${PCAP_CFLAGS}")
        string(REGEX REPLACE "-L([^ ]+).*" "\\1" PCAP_LIB_DIR "${PCAP_LDFLAGS}")
    endif()

    find_path(PCAP_INCLUDE_DIR pcap.h
        HINTS ${PCAP_INCLUDE_DIR}
        PATHS /usr/include /usr/local/include /opt/homebrew/include
    )
    find_library(PCAP_LIBRARY
        NAMES pcap
        HINTS ${PCAP_LIB_DIR}
        PATHS /usr/lib /usr/local/lib /opt/homebrew/lib
    )
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
    REQUIRED_VARS PCAP_LIBRARY PCAP_INCLUDE_DIR
)

if(PCAP_FOUND AND NOT TARGET PCAP::PCAP)
    add_library(PCAP::PCAP UNKNOWN IMPORTED)
    set_target_properties(PCAP::PCAP PROPERTIES
        IMPORTED_LOCATION "${PCAP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
    )
    if(WIN32 AND PACKET_LIBRARY)
        set_property(TARGET PCAP::PCAP APPEND PROPERTY
            INTERFACE_LINK_LIBRARIES "${PACKET_LIBRARY}"
        )
    endif()
endif()

set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
set(PCAP_LIBRARIES ${PCAP_LIBRARY})
mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY PACKET_LIBRARY)
