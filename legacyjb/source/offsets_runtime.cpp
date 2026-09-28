/* Copyright (C) 2025 etaHEN / LightningMods */

extern "C" {
#include <stddef.h>
#include <stdint.h>
#include <ps5/kernel.h>
}

namespace offsets {

static inline size_t rel(intptr_t absolute_va) {
  if (absolute_va == 0 || KERNEL_ADDRESS_DATA_BASE == 0) {
    return (size_t)-1;
  }

  return (size_t)(absolute_va - KERNEL_ADDRESS_DATA_BASE);
}

size_t allproc() { return rel(KERNEL_ADDRESS_ALLPROC); }
size_t security_flags() { return rel(KERNEL_ADDRESS_SECURITY_FLAGS); }
size_t qa_flags() { return rel(KERNEL_ADDRESS_QA_FLAGS); }
size_t utoken_flags() { return rel(KERNEL_ADDRESS_UTOKEN_FLAGS); }
size_t root_vnode() { return rel(KERNEL_ADDRESS_ROOTVNODE); }

} // namespace offsets
