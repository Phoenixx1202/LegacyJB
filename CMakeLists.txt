cmake_minimum_required(VERSION 3.20)

project(LegacyJB C CXX ASM)

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_ROOT}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_ROOT}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_ROOT}/lib")

if(NOT DEFINED V_FW)
  set(V_FW "0x1360" CACHE STRING "PS5 firmware version macro passed as PS5_FW_VERSION")
endif()

if(NOT DEFINED PS5_PAYLOAD_SDK AND DEFINED ENV{PS5_PAYLOAD_SDK})
  set(PS5_PAYLOAD_SDK "$ENV{PS5_PAYLOAD_SDK}" CACHE PATH "Path to ps5-payload-sdk")
endif()

if(NOT PS5_PAYLOAD_SDK)
  message(FATAL_ERROR "PS5_PAYLOAD_SDK is not set. Export it or pass -DPS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk.")
endif()

include_directories(SYSTEM "${PROJECT_ROOT}/include")
include_directories(SYSTEM "${PS5_PAYLOAD_SDK}")
include_directories(SYSTEM "${PS5_PAYLOAD_SDK}/include")

add_subdirectory(libNidResolver)
add_subdirectory(libhijacker)
add_subdirectory(libSelfDecryptor)
add_subdirectory(legacyjb)
