cmake_minimum_required(VERSION 3.20)

project(legacyjb C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT "${CMAKE_CXX_COMPILER_ID}" MATCHES "[Cc]lang")
  message(FATAL_ERROR "${PROJECT_NAME} is meant to be built with clang! CompilerID: ${CMAKE_CXX_COMPILER_ID}")
endif()

set(LEGACY_JB_PAYLOAD_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

set(LEGACY_JB_BASE_FLAGS
  --target=x86_64-sie-ps5
  -DPPR
  -DPS5
  -DPS5_FW_VERSION=${V_FW}
  -Wno-keyword-macro
  -fPIC
  -fPIE
  -march=znver2
  -Wall
  -Werror
  -fstack-protector-all
  -Wno-unused-const-variable
  -O0
)

set(LEGACY_JB_CXX_FLAGS
  ${LEGACY_JB_BASE_FLAGS}
  -DDEBUG
  -gfull
  -gdwarf-2
  -pedantic
  -pedantic-errors
)

add_executable(legacyjb
  "${LEGACY_JB_PAYLOAD_DIR}/source/main.cpp"
  "${LEGACY_JB_PAYLOAD_DIR}/source/offsets_runtime.cpp"
)

set_target_properties(legacyjb PROPERTIES
  OUTPUT_NAME "LegacyJB.elf"
  RUNTIME_OUTPUT_DIRECTORY "${PROJECT_ROOT}/bin"
)

target_compile_options(legacyjb PRIVATE
  $<$<COMPILE_LANGUAGE:C>:${LEGACY_JB_BASE_FLAGS}>
  $<$<COMPILE_LANGUAGE:CXX>:${LEGACY_JB_CXX_FLAGS}>
  $<$<COMPILE_LANGUAGE:ASM>:--target=x86_64-sie-ps5>
)

target_include_directories(legacyjb PRIVATE
  "${LEGACY_JB_PAYLOAD_DIR}/include"
  "${PROJECT_ROOT}/include"
  "${PROJECT_ROOT}/libNidResolver/include"
  "${PS5_PAYLOAD_SDK}"
  "${PS5_PAYLOAD_SDK}/include"
)

target_link_directories(legacyjb PUBLIC "${PROJECT_ROOT}/lib")
add_dependencies(legacyjb hijacker NidResolver SelfDecryptor)
target_link_libraries(legacyjb PUBLIC
  hijacker
  NidResolver
  SelfDecryptor
  SceLibcInternal
  SceSystemService
  SceNet
  SceSysmodule
  SceUserService
  SceNetCtl
  SceSysCore
  kernel_sys
)

add_custom_command(TARGET legacyjb POST_BUILD
  COMMAND ${CMAKE_OBJCOPY}
    --remove-section .debug_info
    --remove-section .debug_abbrev
    --remove-section .debug_line
    --remove-section .debug_str
    --remove-section .debug_loc
    --remove-section .debug_aranges
    --remove-section .debug_ranges
    --remove-section .debug_pubnames
    --remove-section .debug_pubtypes
    --remove-section .debug_frame
    --strip-unneeded
    $<TARGET_FILE:legacyjb>
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:legacyjb>
    "${PROJECT_ROOT}/bin/LegacyJB.bin"
  COMMENT "Stripping and copying LegacyJB.elf as LegacyJB.bin"
)
