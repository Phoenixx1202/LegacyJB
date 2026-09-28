/* Copyright (C) 2025 etaHEN / LightningMods */

#include "legacy_jb.hpp"

#include <hijacker/hijacker.hpp>
#include <offsets.hpp>

extern "C" {
#include "../../libSelfDecryptor/include/SelfDecryptor.h"
#include <ps5/kernel.h>
}

enum Commands : int {
  INVALID_CMD = -1,
  ACTIVE_CMD = 0,
  LAUNCH_CMD,
  PROCLIST_CMD,
  KILL_CMD,
  KILL_APP_CMD,
  JAILBREAK_CMD,
  REMOUNT_FOLDER_CMD,
  ETAHEN_VER_CMD,
  PATCH_LNC_DEBUG_CMD,
  ACTIVATE_DUMPER_CMD,
  TEST_CMD,
  SYMLINK_CMD,
};

struct Command {
  unsigned int magic = 0;
  Commands cmd = INVALID_CMD;
  int PID = -1;
  int ret = 0;
  char msg1[0x500];
  char msg2[0x500];
};

static constexpr unsigned int LEGACY_MAGIC = 0xDEADBEEF;
static constexpr uint16_t LEGACY_PORT = 9028;
static constexpr const char *SANDBOX_BASE = "/mnt/sandbox";
static constexpr const char *JB_FILE_RELPATH = "/download0/etahen_jailbreak";
static constexpr useconds_t POLL_INTERVAL_US = 250 * 1000;
static constexpr const char *LEGACY_LOG_PATH = "/user/data/legacy_jb.log";
static constexpr const char *LEGACY_PREV_LOG_PATH =
    "/user/data/legacy_jb.prev.log";
static constexpr off_t LEGACY_LOG_MAX_BYTES = 256 * 1024;
static constexpr const char *LEGACY_BUILD_TAG =
    "LegacyJB hb-itemzflow-compat 2026-09-28.1";
static constexpr const char *HOMEBREW_STORE_TITLE_ID = "NPXS39041";
static constexpr const char *ITEMZFLOW_TITLE_ID = "ITEM00001";
static constexpr const char *HB_STORE_TEST_PATH =
    "/system/common/lib/.legacyjb_hb_write_test";
static constexpr uint32_t LEGACY_SELF_PROSPERO_MAGIC = 0xEEF51454;
static constexpr uint32_t LEGACY_SELF_ORBIS_MAGIC = 0x1D3D154F;
static constexpr uint32_t LEGACY_PT_LOAD = 0x01;
static constexpr uint32_t LEGACY_PT_SCE_DYNLIBDATA = 0x61000000;
static constexpr uint32_t LEGACY_PT_SCE_VERSION = 0x6FFFFF00;

static volatile sig_atomic_t g_exit_requested = 0;
static pthread_mutex_t g_jailbreak_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_dumper_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_ipc_result_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_server_socket = -1;
static int g_crit_ipc_socket = -1;
static int g_util_ipc_socket = -1;
static bool g_dumper_enabled = false;
static char g_dump_path[512] = {0};
static char g_dump_title[128] = {0};
static char g_last_dump_target_title[10] = {0};
static bool g_last_ipc_error = false;
static int g_dump_opt = 0;

struct LegacyElf64Header {
  unsigned char e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct LegacyElf64ProgramHeader {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

struct LegacySelfHeader {
  uint32_t magic;
  uint8_t version;
  uint8_t mode;
  uint8_t endian;
  uint8_t attributes;
  uint32_t key_type;
  uint16_t header_size;
  uint16_t metadata_size;
  uint64_t file_size;
  uint16_t segment_count;
  uint16_t flags;
  char pad_2[0x4];
};

struct LegacySelfSegmentHeader {
  uint64_t flags;
  uint64_t offset;
  uint64_t compressed_size;
  uint64_t uncompressed_size;
};

enum LegacyLncFlag : uint64_t {
  LegacyFlagNone = 0,
};

struct LegacyLncAppParam {
  uint32_t sz;
  int user_id;
  uint32_t app_opt;
  uint64_t crash_report;
  LegacyLncFlag check_flag;
};

extern "C" int sceUserServiceGetForegroundUser(int *userId);
extern "C" int sceLncUtilLaunchApp(const char *tid, const char *argv[],
                                    LegacyLncAppParam *param);

uint64_t kernel_base = 0;
void *__stack_chk_guard = (void *)0xdeadbeef;

void etaHEN_log(const char *fmt, ...);
void notify(bool show_watermark, const char *text, ...);

struct LegacyIovec {
  const void *iov_base;
  size_t iov_length;
};

#define LEGACY_IOVEC_STRING(value)                                             \
  { value, __builtin_strlen(value) + 1 }
#define LEGACY_IOVEC_EMPTY                                                     \
  { nullptr, 0 }

static void handle_signal(int signal_number) {
  (void)signal_number;
  g_exit_requested = 1;

  if (g_server_socket >= 0) {
    shutdown(g_server_socket, SHUT_RDWR);
    close(g_server_socket);
    g_server_socket = -1;
  }

  if (g_crit_ipc_socket >= 0) {
    shutdown(g_crit_ipc_socket, SHUT_RDWR);
    close(g_crit_ipc_socket);
    g_crit_ipc_socket = -1;
  }

  if (g_util_ipc_socket >= 0) {
    shutdown(g_util_ipc_socket, SHUT_RDWR);
    close(g_util_ipc_socket);
    g_util_ipc_socket = -1;
  }
}

static void ensure_dir(const char *path) {
  if (mkdir(path, 0777) != 0 && errno != EEXIST) {
    printf("[LegacyJB] Failed to create %s: %s\n", path, strerror(errno));
  }
}

static void rotate_log_if_needed(void) {
  struct stat st;
  if (stat(LEGACY_LOG_PATH, &st) != 0 || st.st_size < LEGACY_LOG_MAX_BYTES) {
    return;
  }

  unlink(LEGACY_PREV_LOG_PATH);
  if (rename(LEGACY_LOG_PATH, LEGACY_PREV_LOG_PATH) != 0) {
    FILE *log = fopen(LEGACY_LOG_PATH, "w");
    if (log) {
      fprintf(log, "[LegacyJB] Log truncated after reaching %lld bytes\n",
              (long long)st.st_size);
      fclose(log);
    }
  }
}

static void set_payload_process_name(const char *name) {
  if (name && name[0]) {
    thr_set_name(-1, name);
  }
}

static bool is_valid_title_id(const char *title_id) {
  if (!title_id || strlen(title_id) != 9) {
    return false;
  }

  for (int i = 0; i < 9; i++) {
    char c = title_id[i];
    bool valid_prefix = i < 4 && c >= 'A' && c <= 'Z';
    bool valid_suffix = i >= 4 && c >= '0' && c <= '9';
    if (!valid_prefix && !valid_suffix) {
      return false;
    }
  }

  return true;
}

static bool sandbox_source_to_title_id(const char *source, char *title_id,
                                       size_t title_id_size) {
  if (!source || !title_id || title_id_size < 10) {
    return false;
  }

  const char *underscore = strchr(source, '_');
  size_t length = underscore ? (size_t)(underscore - source) : strlen(source);
  if (length != 9) {
    return false;
  }

  memcpy(title_id, source, length);
  title_id[length] = '\0';
  return is_valid_title_id(title_id);
}

static void format_title_id(String title_id, char *out, size_t out_size) {
  if (!out || out_size == 0) {
    return;
  }

  memset(out, 0, out_size);
  snprintf(out, out_size, "%.9s", title_id.c_str());

  for (size_t i = 0; i < out_size - 1 && out[i]; i++) {
    if (out[i] < 0x20 || out[i] > 0x7E) {
      out[i] = '?';
    }
  }
}

static pid_t find_pid_by_title_id(const char *title_id) {
  if (!title_id || !title_id[0]) {
    return -1;
  }

  for (auto proc : getAllProcs()) {
    String proc_title_id = proc->getTitleId();
    if (strncmp(proc_title_id.c_str(), title_id, 9) == 0) {
      return (pid_t)proc->pid();
    }
  }

  return -1;
}

static bool get_title_id_for_pid(pid_t pid, char *title_id,
                                 size_t title_id_size) {
  if (!title_id || title_id_size < 10) {
    return false;
  }

  title_id[0] = '\0';
  for (auto proc : getAllProcs()) {
    if ((pid_t)proc->pid() != pid) {
      continue;
    }

    String proc_title_id = proc->getTitleId();
    format_title_id(proc_title_id, title_id, title_id_size);
    return is_valid_title_id(title_id);
  }

  return false;
}

static bool is_homebrew_store_title(const char *title_id) {
  return title_id && strncmp(title_id, HOMEBREW_STORE_TITLE_ID, 9) == 0;
}

static bool is_homebrew_store_source(const char *source) {
  return source && strstr(source, HOMEBREW_STORE_TITLE_ID) != nullptr;
}

static bool is_itemzflow_title(const char *title_id) {
  return title_id && strncmp(title_id, ITEMZFLOW_TITLE_ID, 9) == 0;
}

static bool is_itemzflow_source(const char *source) {
  return source && strstr(source, ITEMZFLOW_TITLE_ID) != nullptr;
}

static void log_mount_info(const char *path, const char *label) {
  struct statfs sfs;
  memset(&sfs, 0, sizeof(sfs));

  if (statfs(path, &sfs) != 0) {
    etaHEN_log("HB compat %s statfs(%s) failed: errno=%d (%s)", label, path,
               errno, strerror(errno));
    return;
  }

  etaHEN_log("HB compat %s mount path=%s mnton=%s from=%s type=%s flags=0x%llX "
             "readonly=%s",
             label, path, sfs.f_mntonname, sfs.f_mntfromname,
             sfs.f_fstypename, (unsigned long long)sfs.f_flags,
             (sfs.f_flags & MNT_RDONLY) ? "yes" : "no");
}

static bool test_hb_store_system_write(const char *label) {
  int fd = open(HB_STORE_TEST_PATH, O_CREAT | O_TRUNC | O_WRONLY, 0666);
  if (fd < 0) {
    etaHEN_log("HB compat %s write test failed: %s errno=%d (%s)",
               label, HB_STORE_TEST_PATH, errno, strerror(errno));
    return false;
  }

  const char probe[] = "LegacyJB\n";
  ssize_t written = write(fd, probe, sizeof(probe) - 1);
  int write_errno = errno;
  close(fd);
  unlink(HB_STORE_TEST_PATH);

  if (written != (ssize_t)(sizeof(probe) - 1)) {
    etaHEN_log("HB compat %s write test short write: wrote=%zd errno=%d (%s)",
               label, written, write_errno, strerror(write_errno));
    return false;
  }

  etaHEN_log("HB compat %s write test ok: %s", label, HB_STORE_TEST_PATH);
  return true;
}

static bool remount_system_rw_for_hb_store(void) {
  LegacyIovec iov[] = {
      LEGACY_IOVEC_STRING("fstype"), LEGACY_IOVEC_STRING("exfatfs"),
      LEGACY_IOVEC_STRING("fspath"), LEGACY_IOVEC_STRING("/system"),
      LEGACY_IOVEC_STRING("from"),   LEGACY_IOVEC_STRING("/dev/ssd0.system"),
      LEGACY_IOVEC_STRING("large"),  LEGACY_IOVEC_STRING("yes"),
      LEGACY_IOVEC_STRING("timezone"),
      LEGACY_IOVEC_STRING("static"),
      LEGACY_IOVEC_STRING("async"),     LEGACY_IOVEC_EMPTY,
      LEGACY_IOVEC_STRING("ignoreacl"), LEGACY_IOVEC_EMPTY,
  };

  errno = 0;
  int ret = nmount(reinterpret_cast<struct iovec *>(iov),
                   sizeof(iov) / sizeof(iov[0]), MNT_UPDATE);
  if (ret != 0) {
    etaHEN_log("HB compat remount /system RW failed: ret=%d errno=%d (%s)", ret,
               errno, strerror(errno));
    return false;
  }

  etaHEN_log("HB compat remount /system RW ok");
  return true;
}

static void prepare_homebrew_store_compat(void) {
  etaHEN_log("HB compat preparing Homebrew Store update support");
  log_mount_info("/system/common/lib", "before");

  if (test_hb_store_system_write("before")) {
    etaHEN_log("HB compat /system/common/lib is already writable");
    return;
  }

  if (!remount_system_rw_for_hb_store()) {
    log_mount_info("/system/common/lib", "after failed remount");
    return;
  }

  log_mount_info("/system/common/lib", "after");
  test_hb_store_system_write("after");
}

static bool copy_file_simple(const char *src, const char *dst) {
  if (!src || !dst || !src[0] || !dst[0]) {
    return false;
  }

  char parent[512];
  snprintf(parent, sizeof(parent), "%s", dst);
  char *slash = strrchr(parent, '/');
  if (slash && slash != parent) {
    *slash = '\0';
    for (char *p = parent + 1; *p; p++) {
      if (*p == '/') {
        *p = '\0';
        mkdir(parent, 0777);
        *p = '/';
      }
    }
    mkdir(parent, 0777);
  }

  int in = open(src, O_RDONLY);
  if (in < 0) {
    return false;
  }

  int out = open(dst, O_CREAT | O_TRUNC | O_WRONLY, 0666);
  if (out < 0) {
    close(in);
    return false;
  }

  char buffer[8192];
  bool ok = true;
  ssize_t got;
  while ((got = read(in, buffer, sizeof(buffer))) > 0) {
    char *ptr = buffer;
    ssize_t left = got;
    while (left > 0) {
      ssize_t written = write(out, ptr, (size_t)left);
      if (written <= 0) {
        ok = false;
        break;
      }
      ptr += written;
      left -= written;
    }
    if (!ok) {
      break;
    }
  }

  if (got < 0) {
    ok = false;
  }

  close(out);
  close(in);
  return ok;
}

static uint64_t calculate_dir_size_simple(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }

  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }

  if (!S_ISDIR(st.st_mode)) {
    return (uint64_t)st.st_size;
  }

  DIR *dir = opendir(path);
  if (!dir) {
    return 0;
  }

  uint64_t total = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != nullptr) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    char child[1024];
    int written = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
    if (written <= 0 || (size_t)written >= sizeof(child)) {
      continue;
    }

    total += calculate_dir_size_simple(child);
  }

  closedir(dir);
  return total;
}

static bool test_sb_file_simple(const char *filename) {
  if (!filename || !filename[0]) {
    return false;
  }

  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    etaHEN_log("Itemzflow compat SB test open failed: %s errno=%d (%s)",
               filename, errno, strerror(errno));
    return false;
  }

  struct stat file_info;
  if (fstat(fd, &file_info) != 0) {
    etaHEN_log("Itemzflow compat SB test fstat failed: %s errno=%d (%s)",
               filename, errno, strerror(errno));
    close(fd);
    return false;
  }

  char buffer[0x1024];
  off_t file_size = file_info.st_size;
  bool ok = true;

  if (read(fd, buffer, sizeof(buffer)) < 0) {
    ok = false;
  }

  off_t middle = file_size / 2 > (off_t)sizeof(buffer)
                     ? file_size / 2 - (off_t)sizeof(buffer) / 2
                     : 0;
  if (ok && (lseek(fd, middle, SEEK_SET) < 0 ||
             read(fd, buffer, sizeof(buffer)) < 0)) {
    ok = false;
  }

  off_t end = file_size > (off_t)sizeof(buffer)
                  ? file_size - (off_t)sizeof(buffer)
                  : 0;
  if (ok &&
      (lseek(fd, end, SEEK_SET) < 0 || read(fd, buffer, sizeof(buffer)) < 0)) {
    ok = false;
  }

  if (!ok) {
    etaHEN_log("Itemzflow compat SB test read failed: %s errno=%d (%s)",
               filename, errno, strerror(errno));
  }

  close(fd);
  return ok;
}

static bool starts_with_path(const char *path, const char *prefix) {
  return path && prefix && strncmp(path, prefix, strlen(prefix)) == 0;
}

static bool is_decrypt_path_allowed(const char *src, const char *dst) {
  if (!src || !dst) {
    return false;
  }

  bool src_ok = starts_with_path(src, "/mnt/sandbox/pfsmnt/");
  bool dst_ok = starts_with_path(dst, "/mnt/usb0/") ||
                starts_with_path(dst, "/mnt/usb1/");
  return src_ok && dst_ok;
}

static bool ends_with_ci(const char *text, const char *suffix) {
  if (!text || !suffix) {
    return false;
  }

  size_t text_len = strlen(text);
  size_t suffix_len = strlen(suffix);
  if (suffix_len > text_len) {
    return false;
  }

  return strcasecmp(text + text_len - suffix_len, suffix) == 0;
}

static bool is_decrypt_candidate(const char *path) {
  if (!path || !path[0]) {
    return false;
  }

  const char *name = strrchr(path, '/');
  name = name ? name + 1 : path;
  if (strcmp(name, "right.sprx") == 0) {
    return false;
  }

  return ends_with_ci(name, ".self") || ends_with_ci(name, ".elf") ||
         ends_with_ci(name, ".bin") || ends_with_ci(name, ".prx") ||
         ends_with_ci(name, ".sprx") || ends_with_ci(name, ".dll");
}

static void set_last_ipc_error(bool error) {
  pthread_mutex_lock(&g_ipc_result_lock);
  g_last_ipc_error = error;
  pthread_mutex_unlock(&g_ipc_result_lock);
}

static bool get_last_ipc_error(void) {
  pthread_mutex_lock(&g_ipc_result_lock);
  bool error = g_last_ipc_error;
  pthread_mutex_unlock(&g_ipc_result_lock);
  return error;
}

static bool read_u32_magic(const char *path, uint32_t *magic) {
  if (!path || !magic) {
    return false;
  }

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return false;
  }

  ssize_t got = read(fd, magic, sizeof(*magic));
  close(fd);
  return got == (ssize_t)sizeof(*magic);
}

static bool has_self_magic(const char *path) {
  uint32_t magic = 0;
  if (!read_u32_magic(path, &magic)) {
    return false;
  }

  return magic == LEGACY_SELF_PROSPERO_MAGIC ||
         magic == LEGACY_SELF_ORBIS_MAGIC;
}

static int decrypt_self_legacy_map(const char *path, const char *out_path) {
  int self_fd = open(path, O_RDONLY);
  if (self_fd < 0) {
    etaHEN_log("Itemzflow compat legacy decrypt open failed: %s errno=%d (%s)",
               path, errno, strerror(errno));
    return -errno;
  }

  char *self_file_data =
      (char *)mmap(nullptr, 0x1000, PROT_READ, MAP_SHARED, self_fd, 0);
  if (self_file_data == MAP_FAILED) {
    int saved_errno = errno;
    etaHEN_log("Itemzflow compat legacy decrypt header mmap failed: %s "
               "errno=%d (%s)",
               path, saved_errno, strerror(saved_errno));
    close(self_fd);
    return -saved_errno;
  }

  LegacySelfHeader *header = (LegacySelfHeader *)self_file_data;
  if (header->magic != LEGACY_SELF_PROSPERO_MAGIC &&
      header->magic != LEGACY_SELF_ORBIS_MAGIC) {
    munmap(self_file_data, 0x1000);
    close(self_fd);
    return -5;
  }

  LegacyElf64Header *elf_header = (LegacyElf64Header *)(
      self_file_data + sizeof(LegacySelfHeader) +
      sizeof(LegacySelfSegmentHeader) * header->segment_count);
  LegacyElf64ProgramHeader *start_phdrs = (LegacyElf64ProgramHeader *)(
      (char *)elf_header + sizeof(LegacyElf64Header));

  uint64_t final_file_size = 0;
  for (int i = 0; i < elf_header->e_phnum; i++) {
    LegacyElf64ProgramHeader *phdr = &start_phdrs[i];
    uint64_t end = phdr->p_offset + phdr->p_filesz;
    if (end > final_file_size) {
      final_file_size = end;
    }
  }

  if (final_file_size == 0) {
    munmap(self_file_data, 0x1000);
    close(self_fd);
    return -EINVAL;
  }

  char *out_file_data = (char *)mmap(nullptr, final_file_size,
                                     PROT_READ | PROT_WRITE,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (out_file_data == MAP_FAILED) {
    int saved_errno = errno;
    etaHEN_log("Itemzflow compat legacy decrypt output mmap failed: %s "
               "errno=%d (%s)",
               path, saved_errno, strerror(saved_errno));
    munmap(self_file_data, 0x1000);
    close(self_fd);
    return -saved_errno;
  }

  memcpy(out_file_data, elf_header, sizeof(LegacyElf64Header));
  memcpy(out_file_data + sizeof(LegacyElf64Header), start_phdrs,
         elf_header->e_phnum * sizeof(LegacyElf64ProgramHeader));

  int ret = 0;
  for (uint64_t i = 0; i < elf_header->e_phnum; i++) {
    LegacyElf64ProgramHeader *phdr = &start_phdrs[i];
    if (phdr->p_filesz == 0) {
      continue;
    }

    if (phdr->p_type == LEGACY_PT_LOAD ||
        phdr->p_type == LEGACY_PT_SCE_DYNLIBDATA) {
      void *segment_data =
          mmap(nullptr, phdr->p_filesz, PROT_READ, MAP_SHARED | 0x80000,
               self_fd, (off_t)(i << 32));
      if (segment_data == MAP_FAILED) {
        int saved_errno = errno;
        etaHEN_log("Itemzflow compat legacy decrypt segment mmap failed: %s "
                   "seg=%llu type=0x%X filesz=0x%llX offset=0x%llX "
                   "errno=%d (%s)",
                   path, (unsigned long long)i, phdr->p_type,
                   (unsigned long long)phdr->p_filesz,
                   (unsigned long long)phdr->p_offset, saved_errno,
                   strerror(saved_errno));
        ret = -saved_errno;
        break;
      }

      memcpy(out_file_data + phdr->p_offset, segment_data, phdr->p_filesz);
      munmap(segment_data, phdr->p_filesz);
    } else if (phdr->p_type == LEGACY_PT_SCE_VERSION) {
      if (lseek(self_fd, phdr->p_offset, SEEK_SET) < 0 ||
          read(self_fd, out_file_data + phdr->p_offset, phdr->p_filesz) <
              (ssize_t)phdr->p_filesz) {
        int saved_errno = errno;
        etaHEN_log("Itemzflow compat legacy decrypt version read failed: %s "
                   "errno=%d (%s)",
                   path, saved_errno, strerror(saved_errno));
        ret = -saved_errno;
        break;
      }
    }
  }

  munmap(self_file_data, 0x1000);
  close(self_fd);

  if (ret == 0) {
    int out_fd = open(out_path, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (out_fd < 0) {
      int saved_errno = errno;
      etaHEN_log("Itemzflow compat legacy decrypt output open failed: %s "
                 "errno=%d (%s)",
                 out_path, saved_errno, strerror(saved_errno));
      ret = -saved_errno;
    } else {
      ssize_t written = write(out_fd, out_file_data, final_file_size);
      if (written != (ssize_t)final_file_size) {
        int saved_errno = errno;
        etaHEN_log("Itemzflow compat legacy decrypt output write failed: %s "
                   "written=%zd expected=%llu errno=%d (%s)",
                   out_path, written, (unsigned long long)final_file_size,
                   saved_errno, strerror(saved_errno));
        ret = -EIO;
      }
      close(out_fd);
    }
  }

  munmap(out_file_data, final_file_size);
  return ret;
}

static bool decrypt_dir_targeted(const char *src_dir, const char *dst_dir,
                                 int *num_success, int *num_failed) {
  if (!src_dir || !dst_dir || !src_dir[0] || !dst_dir[0]) {
    return false;
  }

  DIR *dir = opendir(src_dir);
  if (!dir) {
    etaHEN_log("Itemzflow compat decrypt open failed: %s errno=%d (%s)",
               src_dir, errno, strerror(errno));
    return false;
  }

  mkdir(dst_dir, 0777);
  bool ok = true;
  struct dirent *entry;
  while ((entry = readdir(dir)) != nullptr && !g_exit_requested) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    char src_path[1024];
    char dst_path[1024];
    int src_len = snprintf(src_path, sizeof(src_path), "%s/%s", src_dir,
                           entry->d_name);
    int dst_len = snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir,
                           entry->d_name);
    if (src_len <= 0 || dst_len <= 0 || (size_t)src_len >= sizeof(src_path) ||
        (size_t)dst_len >= sizeof(dst_path)) {
      ok = false;
      continue;
    }

    struct stat st;
    if (lstat(src_path, &st) != 0) {
      etaHEN_log("Itemzflow compat decrypt stat failed: %s errno=%d (%s)",
                 src_path, errno, strerror(errno));
      ok = false;
      continue;
    }

    if (S_ISDIR(st.st_mode)) {
      mkdir(dst_path, 0777);
      if (!decrypt_dir_targeted(src_path, dst_path, num_success, num_failed)) {
        ok = false;
      }
      continue;
    }

    if (!S_ISREG(st.st_mode) || !is_decrypt_candidate(src_path)) {
      continue;
    }

    if (!has_self_magic(src_path)) {
      continue;
    }

    int before_failed = num_failed ? *num_failed : 0;
    int ret = decrypt_self_legacy_map(src_path, dst_path);
    if (ret != 0) {
      ret = decrypt_self_by_path(src_path, dst_path, num_success, num_failed);
    } else if (num_success) {
      (*num_success)++;
    }

    int after_failed = num_failed ? *num_failed : before_failed;
    if (ret != 0 && after_failed > before_failed) {
      etaHEN_log("Itemzflow compat decrypt failed: %s ret=%d", src_path, ret);
      ok = false;
    }
  }

  closedir(dir);
  return ok;
}

static bool is_delete_path_allowed(const char *path) {
  if (!path) {
    return false;
  }

  return strcmp(path, "/user/app/ITEM00001/downloads") == 0 ||
         strcmp(path, "/system_ex/app/DUMP00000") == 0 ||
         strncmp(path, "/data/itemzflow/", strlen("/data/itemzflow/")) == 0;
}

static bool delete_path_recursive(const char *path) {
  if (!path || !path[0]) {
    return false;
  }

  struct stat st;
  if (lstat(path, &st) != 0) {
    return errno == ENOENT;
  }

  if (!S_ISDIR(st.st_mode)) {
    return unlink(path) == 0 || errno == ENOENT;
  }

  DIR *dir = opendir(path);
  if (!dir) {
    return false;
  }

  bool ok = true;
  struct dirent *entry;
  while ((entry = readdir(dir)) != nullptr) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    char child[1024];
    int written = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
    if (written <= 0 || (size_t)written >= sizeof(child)) {
      ok = false;
      continue;
    }

    if (!delete_path_recursive(child)) {
      ok = false;
    }
  }
  closedir(dir);

  if (rmdir(path) != 0 && errno != ENOENT) {
    ok = false;
  }

  return ok;
}

static bool json_extract_string(const char *json, const char *key, char *out,
                                size_t out_size) {
  if (!json || !key || !out || out_size == 0) {
    return false;
  }

  out[0] = '\0';
  char needle[64];
  snprintf(needle, sizeof(needle), "\"%s\"", key);
  const char *ptr = strstr(json, needle);
  if (!ptr) {
    return false;
  }

  ptr = strchr(ptr, ':');
  if (!ptr) {
    return false;
  }

  ptr++;
  while (*ptr == ' ' || *ptr == '\t') {
    ptr++;
  }

  if (*ptr != '"') {
    return false;
  }

  ptr++;
  size_t i = 0;
  while (*ptr && *ptr != '"' && i + 1 < out_size) {
    if (*ptr == '\\' && ptr[1]) {
      ptr++;
    }
    out[i++] = *ptr++;
  }
  out[i] = '\0';
  return i > 0;
}

static bool json_extract_int(const char *json, const char *key, int *out) {
  if (!json || !key || !out) {
    return false;
  }

  char needle[64];
  snprintf(needle, sizeof(needle), "\"%s\"", key);
  const char *ptr = strstr(json, needle);
  if (!ptr) {
    return false;
  }

  ptr = strchr(ptr, ':');
  if (!ptr) {
    return false;
  }

  ptr++;
  while (*ptr == ' ' || *ptr == '\t' || *ptr == '"') {
    ptr++;
  }

  *out = atoi(ptr);
  return true;
}

static void ipc_reply(int client, DaemonCommands response_cmd, bool error,
                      const char *out_var) {
  IPCMessage output;
  memset(&output, 0, sizeof(output));
  output.magic = 0xDEADBABE;
  output.cmd = response_cmd;
  output.error = error ? -1 : 0;
  snprintf(output.msg, sizeof(output.msg), "{\"res\":%d, \"var\":\"%s\"}",
           error ? -1 : 0, out_var && out_var[0] ? out_var : "Nothing");
  send(client, &output, sizeof(output), MSG_NOSIGNAL);
}

static bool ipc_socket_is_active(const char *path) {
  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) {
    return false;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
  bool active = connect(sock, (struct sockaddr *)&addr, SUN_LEN(&addr)) == 0;
  close(sock);
  return active;
}

static void prepare_itemzflow_filesystem(void) {
  ensure_dir("/data");
  ensure_dir("/data/itemzflow");
  ensure_dir("/data/itemzflow/plugins");
  ensure_dir("/data/itemzflow/logs");
  ensure_dir("/data/itemzflow/covers");
  ensure_dir("/user/app/ITEM00001/downloads");
  etaHEN_log("Itemzflow compat filesystem prepared");
}

static bool get_attachable_non_itemz_title(char *title_id, size_t title_size) {
  if (!title_id || title_size < 10) {
    return false;
  }

  title_id[0] = '\0';
  for (auto proc : getAllProcs()) {
    char proc_title_buf[10] = {0};
    format_title_id(proc->getTitleId(), proc_title_buf,
                    sizeof(proc_title_buf));
    if (!is_valid_title_id(proc_title_buf)) {
      continue;
    }

    if (strncmp(proc_title_buf, ITEMZFLOW_TITLE_ID, 9) == 0 ||
        strncmp(proc_title_buf, "DUMP00000", 9) == 0 ||
        strncmp(proc_title_buf, "NPXS", 4) == 0) {
      continue;
    }

    char sandbox_path[128];
    snprintf(sandbox_path, sizeof(sandbox_path), "/mnt/sandbox/pfsmnt/%s-app0",
             proc_title_buf);
    struct stat st;
    if (stat(sandbox_path, &st) != 0) {
      continue;
    }

    strncpy(title_id, proc_title_buf, title_size - 1);
    title_id[title_size - 1] = '\0';
    return true;
  }

  return false;
}

static void set_dumper_state(const char *path, const char *title, int opt) {
  pthread_mutex_lock(&g_dumper_lock);
  snprintf(g_dump_path, sizeof(g_dump_path), "%s",
           path && path[0] ? path : "/mnt/usb0/");
  snprintf(g_dump_title, sizeof(g_dump_title), "%s",
           title && title[0] ? title : "Unknown");
  g_dump_opt = opt;
  g_dumper_enabled = true;
  pthread_mutex_unlock(&g_dumper_lock);
}

static bool take_dumper_state(char *path, size_t path_size, char *title,
                              size_t title_size, int *opt) {
  pthread_mutex_lock(&g_dumper_lock);
  if (!g_dumper_enabled) {
    pthread_mutex_unlock(&g_dumper_lock);
    return false;
  }

  snprintf(path, path_size, "%s", g_dump_path);
  snprintf(title, title_size, "%s", g_dump_title);
  if (opt) {
    *opt = g_dump_opt;
  }
  g_dumper_enabled = false;
  pthread_mutex_unlock(&g_dumper_lock);
  return true;
}

static void remember_dump_target_title(const char *title_id) {
  pthread_mutex_lock(&g_dumper_lock);
  snprintf(g_last_dump_target_title, sizeof(g_last_dump_target_title), "%s",
           title_id && title_id[0] ? title_id : "");
  pthread_mutex_unlock(&g_dumper_lock);
}

static bool get_last_dump_target_title(char *title_id, size_t title_id_size) {
  if (!title_id || title_id_size < 10) {
    return false;
  }

  pthread_mutex_lock(&g_dumper_lock);
  snprintf(title_id, title_id_size, "%s", g_last_dump_target_title);
  pthread_mutex_unlock(&g_dumper_lock);
  return is_valid_title_id(title_id);
}

static int launch_title_simple(const char *title_id) {
  if (!is_valid_title_id(title_id)) {
    return -1;
  }

  int user_id = 0;
  int user_ret = sceUserServiceGetForegroundUser(&user_id);
  if (user_ret != 0) {
    etaHEN_log("Itemzflow compat launch foreground user failed: 0x%X",
               user_ret);
    return user_ret;
  }

  LegacyLncAppParam param = {sizeof(LegacyLncAppParam),
                             user_id,
                             0,
                             0,
                             LegacyFlagNone};
  int ret = sceLncUtilLaunchApp(title_id, nullptr, &param);
  etaHEN_log("Itemzflow compat launch %s returned 0x%X", title_id, ret);
  return ret;
}

struct DecryptJob {
  char src_path[512];
  char dest_path[512];
  char target_title_id[10];
};

static void *run_decrypt_job(void *arg) {
  DecryptJob *job = (DecryptJob *)arg;
  set_payload_process_name("LegacyJB-decrypt");

  etaHEN_log("Itemzflow compat decrypt job started: %s -> %s target=%s",
             job->src_path, job->dest_path,
             job->target_title_id[0] ? job->target_title_id : "unknown");
  notify(false, "LegacyJB decrypt started");

  if (is_valid_title_id(job->target_title_id)) {
    launch_title_simple(job->target_title_id);
    sleep(6);
  }

  mkdir(job->dest_path, 0777);
  int num_success = 0;
  int num_failed = 0;
  bool ok = decrypt_dir_targeted(job->src_path, job->dest_path, &num_success,
                                 &num_failed);

  int marker = open("/data/decryption_done.log", O_CREAT | O_TRUNC | O_WRONLY,
                    0666);
  if (marker >= 0) {
    char marker_text[128];
    int len = snprintf(marker_text, sizeof(marker_text),
                       "ok=%d success=%d failed=%d\n", ok ? 1 : 0,
                       num_success, num_failed);
    if (len > 0) {
      write(marker, marker_text, (size_t)len);
    }
    close(marker);
  }

  etaHEN_log("Itemzflow compat decrypt job finished: ok=%s success=%d "
             "failed=%d",
             ok ? "yes" : "no", num_success, num_failed);
  set_last_ipc_error(!ok);
  notify(false, ok ? "LegacyJB decrypt finished" : "LegacyJB decrypt failed");
  launch_title_simple("DUMP00000");

  free(job);
  return nullptr;
}

static void *run_dumper_monitor(void *) {
  etaHEN_log("Itemzflow dumper monitor started");
  while (!g_exit_requested) {
    pthread_mutex_lock(&g_dumper_lock);
    bool armed = g_dumper_enabled;
    pthread_mutex_unlock(&g_dumper_lock);
    if (!armed) {
      usleep(500 * 1000);
      continue;
    }

    char target_title_id[10] = {0};
    if (!get_attachable_non_itemz_title(target_title_id,
                                        sizeof(target_title_id))) {
      usleep(500 * 1000);
      continue;
    }

    char path[512];
    char title[128];
    int opt = 0;
    if (!take_dumper_state(path, sizeof(path), title, sizeof(title), &opt)) {
      continue;
    }

    int user_id = 0;
    int user_ret = sceUserServiceGetForegroundUser(&user_id);
    if (user_ret != 0) {
      etaHEN_log("Itemzflow dumper foreground user failed: 0x%X", user_ret);
      set_dumper_state(path, title, opt);
      usleep(1000 * 1000);
      continue;
    }

    char opt_text[32];
    snprintf(opt_text, sizeof(opt_text), "%d", opt);
    const char *argv[5] = {title, path, target_title_id, opt_text, nullptr};
    LegacyLncAppParam param = {sizeof(LegacyLncAppParam),
                               user_id,
                               0,
                               0,
                               LegacyFlagNone};

    etaHEN_log("Itemzflow dumper launching DUMP00000 title='%s' path='%s' "
               "target='%s' opt=%d",
               title, path, target_title_id, opt);
    remember_dump_target_title(target_title_id);
    int ret = sceLncUtilLaunchApp("DUMP00000", argv, &param);
    etaHEN_log("Itemzflow dumper sceLncUtilLaunchApp returned 0x%X", ret);
  }

  etaHEN_log("Itemzflow dumper monitor stopped");
  return nullptr;
}

static int start_ipc_listener(const char *path, const char *name) {
  if (ipc_socket_is_active(path)) {
    etaHEN_log("Itemzflow compat %s socket is already active", name);
    return -1;
  }

  unlink(path);
  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) {
    etaHEN_log("Itemzflow compat %s socket create failed: %s", name,
               strerror(errno));
    return -1;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if (bind(sock, (struct sockaddr *)&addr, SUN_LEN(&addr)) != 0) {
    etaHEN_log("Itemzflow compat %s socket bind failed: %s", name,
               strerror(errno));
    close(sock);
    return -1;
  }

  if (listen(sock, 16) != 0) {
    etaHEN_log("Itemzflow compat %s listen failed: %s", name, strerror(errno));
    close(sock);
    unlink(path);
    return -1;
  }

  etaHEN_log("Itemzflow compat %s IPC listener started", name);
  return sock;
}

struct IpcCompatServer {
  const char *path;
  const char *name;
  bool util;
  int *socket_slot;
};

static void handle_ipc_compat_client(int client, bool util) {
  IPCMessage input;
  while (!g_exit_requested) {
    ssize_t got = recv(client, &input, sizeof(input), MSG_NOSIGNAL);
    if (got <= 0) {
      break;
    }

    if ((size_t)got != sizeof(input) || input.magic != 0xDEADBABE) {
      etaHEN_log("Itemzflow compat invalid IPC message: got=%zd magic=0x%X",
                 got, input.magic);
      ipc_reply(client, util ? BREW_UTIL_RETURN_VALUE : BREW_RETURN_VALUE, true,
                "Invalid");
      continue;
    }

    etaHEN_log("Itemzflow compat %s command 0x%X json='%s'",
               util ? "util" : "crit", input.cmd, input.msg);

    char out[64];
    switch (input.cmd) {
    case BREW_TEST_CONNECTION:
    case BREW_UTIL_TEST_CONNECTION:
      ipc_reply(client, util ? BREW_UTIL_RETURN_VALUE : BREW_RETURN_VALUE,
                false, "Nothing");
      break;
    case BREW_DAEMON_PID:
    case BREW_UTIL_DAEMON_PID:
      snprintf(out, sizeof(out), "%d", getpid());
      ipc_reply(client, util ? BREW_UTIL_RETURN_VALUE : BREW_RETURN_VALUE,
                false, out);
      break;
    case BREW_STAT_CMD: {
      char path[512];
      struct stat st;
      if (json_extract_string(input.msg, "path", path, sizeof(path)) &&
          stat(path, &st) == 0) {
        snprintf(out, sizeof(out), "%lld", (long long)st.st_size);
        ipc_reply(client, BREW_RETURN_VALUE, false, out);
      } else {
        etaHEN_log("Itemzflow compat stat failed: json='%s' errno=%d (%s)",
                   input.msg, errno, strerror(errno));
        ipc_reply(client, BREW_RETURN_VALUE, true, "StatFailed");
      }
      break;
    }
    case BREW_CALC_DIR_SIZE: {
      char path[512];
      if (json_extract_string(input.msg, "path", path, sizeof(path))) {
        uint64_t size = calculate_dir_size_simple(path);
        char size_text[64];
        snprintf(size_text, sizeof(size_text), "%llu",
                 (unsigned long long)size);
        etaHEN_log("Itemzflow compat calculated size %s => %s", path,
                   size_text);
        ipc_reply(client, BREW_RETURN_VALUE, false, size_text);
      } else {
        etaHEN_log("Itemzflow compat calc dir size missing path: json='%s'",
                   input.msg);
        ipc_reply(client, BREW_RETURN_VALUE, true, "CalcDirSizeFailed");
      }
      break;
    }
    case BREW_COPY_FILE: {
      char src[512];
      char dst[512];
      if (json_extract_string(input.msg, "path", src, sizeof(src)) &&
          json_extract_string(input.msg, "dest", dst, sizeof(dst)) &&
          copy_file_simple(src, dst)) {
        ipc_reply(client, BREW_RETURN_VALUE, false, "Nothing");
      } else {
        etaHEN_log("Itemzflow compat copy failed: json='%s' errno=%d (%s)",
                   input.msg, errno, strerror(errno));
        ipc_reply(client, BREW_RETURN_VALUE, true, "CopyFailed");
      }
      break;
    }
    case BREW_DELETE_DIR: {
      char path[512];
      if (!json_extract_string(input.msg, "path", path, sizeof(path))) {
        etaHEN_log("Itemzflow compat delete missing path: json='%s'",
                   input.msg);
        ipc_reply(client, BREW_RETURN_VALUE, true, "DeleteFailed");
      } else if (!is_delete_path_allowed(path)) {
        etaHEN_log("Itemzflow compat refused delete path: %s", path);
        ipc_reply(client, BREW_RETURN_VALUE, true, "DeleteRefused");
      } else if (delete_path_recursive(path)) {
        etaHEN_log("Itemzflow compat deleted path: %s", path);
        ipc_reply(client, BREW_RETURN_VALUE, false, "Nothing");
      } else {
        etaHEN_log("Itemzflow compat delete failed: %s errno=%d (%s)", path,
                   errno, strerror(errno));
        ipc_reply(client, BREW_RETURN_VALUE, true, "DeleteFailed");
      }
      break;
    }
    case BREW_TEST_SB_FILE: {
      char path[512];
      if (json_extract_string(input.msg, "path", path, sizeof(path)) &&
          test_sb_file_simple(path)) {
        ipc_reply(client, BREW_RETURN_VALUE, false, "Nothing");
      } else {
        etaHEN_log("Itemzflow compat SB test failed: json='%s'", input.msg);
        ipc_reply(client, BREW_RETURN_VALUE, true, "SBTestFailed");
      }
      break;
    }
    case BREW_ACTIVATE_DUMPER: {
      char dump_path[512];
      char dump_title[128];
      if (!json_extract_string(input.msg, "dump_path", dump_path,
                               sizeof(dump_path))) {
        snprintf(dump_path, sizeof(dump_path), "/mnt/usb0/");
      }
      if (!json_extract_string(input.msg, "dump_title", dump_title,
                               sizeof(dump_title))) {
        snprintf(dump_title, sizeof(dump_title), "Unknown");
      }
      int dump_opt = 0;
      if (!json_extract_int(input.msg, "dump_opt", &dump_opt) ||
          dump_opt < 0) {
        dump_opt = 0;
      }

      set_dumper_state(dump_path, dump_title, dump_opt);
      etaHEN_log("Itemzflow compat dumper armed title='%s' path='%s' opt=%d",
                 dump_title, dump_path, dump_opt);
      ipc_reply(client, BREW_RETURN_VALUE, false, "Nothing");
      break;
    }
    case BREW_DECRYPT_DIR: {
      char src_path[512];
      char dest_path[512];
      if (!json_extract_string(input.msg, "src_path", src_path,
                               sizeof(src_path)) ||
          !json_extract_string(input.msg, "dest_path", dest_path,
                               sizeof(dest_path))) {
        etaHEN_log("Itemzflow compat decrypt missing paths: json='%s'",
                   input.msg);
        ipc_reply(client, BREW_RETURN_VALUE, true, "DecryptMissingPaths");
        break;
      }

      if (!is_decrypt_path_allowed(src_path, dest_path)) {
        etaHEN_log("Itemzflow compat refused decrypt: %s -> %s", src_path,
                   dest_path);
        ipc_reply(client, BREW_RETURN_VALUE, true, "DecryptRefused");
        break;
      }

      DecryptJob *job = (DecryptJob *)calloc(1, sizeof(DecryptJob));
      if (!job) {
        ipc_reply(client, BREW_RETURN_VALUE, true, "DecryptNoMemory");
        break;
      }

      snprintf(job->src_path, sizeof(job->src_path), "%s", src_path);
      snprintf(job->dest_path, sizeof(job->dest_path), "%s", dest_path);
      get_last_dump_target_title(job->target_title_id,
                                 sizeof(job->target_title_id));

      pthread_t thread;
      int thread_ret = pthread_create(&thread, nullptr, run_decrypt_job, job);
      if (thread_ret != 0) {
        etaHEN_log("Itemzflow compat decrypt thread failed: %d", thread_ret);
        free(job);
        ipc_reply(client, BREW_RETURN_VALUE, true, "DecryptThreadFailed");
        break;
      }

      pthread_detach(thread);
      etaHEN_log("Itemzflow compat decrypt queued: %s -> %s", src_path,
                 dest_path);
      ipc_reply(client, BREW_RETURN_VALUE, false, "Nothing");
      break;
    }
    case BREW_LAST_RET: {
      bool error = get_last_ipc_error();
      ipc_reply(client, BREW_RETURN_VALUE, error, error ? "1" : "0");
      break;
    }
    default:
      etaHEN_log("Itemzflow compat unsupported %s command 0x%X",
                 util ? "util" : "crit", input.cmd);
      ipc_reply(client, util ? BREW_UTIL_RETURN_VALUE : BREW_RETURN_VALUE, true,
                "Unsupported");
      break;
    }
  }
}

static void *run_ipc_compat_server(void *arg) {
  IpcCompatServer *server = (IpcCompatServer *)arg;
  int sock = start_ipc_listener(server->path, server->name);
  *server->socket_slot = sock;
  if (sock < 0) {
    return nullptr;
  }

  while (!g_exit_requested) {
    int client = accept(sock, nullptr, nullptr);
    if (client < 0) {
      if (!g_exit_requested) {
        etaHEN_log("Itemzflow compat %s accept failed: %s", server->name,
                   strerror(errno));
      }
      continue;
    }

    etaHEN_log("Itemzflow compat %s IPC client connected", server->name);
    handle_ipc_compat_client(client, server->util);
    close(client);
  }

  close(sock);
  unlink(server->path);
  *server->socket_slot = -1;
  return nullptr;
}

static void prepare_itemzflow_compat(void) {
  etaHEN_log("Itemzflow compat preparing support");
  prepare_itemzflow_filesystem();
}

static void log_process_snapshot(const char *title_id, pid_t requested_pid) {
  int logged = 0;
  etaHEN_log("Process snapshot: requested PID %d, wanted title '%s'",
             requested_pid, title_id && title_id[0] ? title_id : "none");

  for (auto proc : getAllProcs()) {
    pid_t proc_pid = (pid_t)proc->pid();
    String proc_title = proc->getTitleId();
    char proc_title_buf[10] = {0};
    format_title_id(proc_title, proc_title_buf, sizeof(proc_title_buf));

    bool has_title = proc_title_buf[0] && strncmp(proc_title_buf, "         ", 9) != 0;
    bool title_matches =
        title_id && title_id[0] && strncmp(proc_title_buf, title_id, 9) == 0;
    bool should_log = proc_pid == requested_pid || title_matches;

    if (!should_log && has_title && logged < 10) {
      should_log = true;
    }

    if (!should_log) {
      continue;
    }

    String proc_path = proc->getPath();
    etaHEN_log("  proc pid=%d title='%s' path='%s'%s", proc_pid,
               proc_title_buf[0] ? proc_title_buf : "empty",
               proc_path.c_str(), title_matches ? " [title match]" : "");
    logged++;
  }

  if (logged == 0) {
    etaHEN_log("  no visible process entries matched the request");
  }
}

void etaHEN_log(const char *fmt, ...) {
  char message[2048] = {0};

  va_list args;
  va_start(args, fmt);
  vsnprintf(message, sizeof(message), fmt, args);
  va_end(args);

  printf("[LegacyJB] %s\n", message);

  rotate_log_if_needed();

  FILE *log = fopen(LEGACY_LOG_PATH, "a");
  if (log) {
    fprintf(log, "[LegacyJB] %s\n", message);
    fclose(log);
  }
}

void notify(bool show_watermark, const char *text, ...) {
  char message[1024] = {0};
  char formatted[900] = {0};

  va_list args;
  va_start(args, text);
  vsnprintf(formatted, sizeof(formatted), text, args);
  va_end(args);

  snprintf(message, sizeof(message), "%s%s",
           show_watermark ? "[LegacyJB] " : "", formatted);
  etaHEN_log("Notify: %s", message);

  OrbisNotificationRequest req;
  memset(&req, 0, sizeof(req));
  req.type = 0;
  req.unk3 = 0;
  req.use_icon_image_uri = 1;
  req.target_id = -1;
  strncpy(req.message, message, sizeof(req.message) - 1);
  strncpy(req.uri, "cxml://psnotification/tex_icon_system",
          sizeof(req.uri) - 1);

  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

extern "C" void __stack_chk_fail(void) {
  etaHEN_log("Stack smashing detected");
  abort();
}

static void reply_error(int sock) {
  Command cmd;
  memset(&cmd, 0, sizeof(cmd));
  cmd.ret = -1;
  send(sock, &cmd, sizeof(cmd), MSG_NOSIGNAL);
}

static void reply_ok(int sock) {
  Command cmd;
  memset(&cmd, 0, sizeof(cmd));
  send(sock, &cmd, sizeof(cmd), MSG_NOSIGNAL);
}

static bool do_jailbreak(pid_t pid, const char *source) {
  if (pid <= 0) {
    etaHEN_log("Invalid PID from %s: %d", source ? source : "unknown", pid);
    return false;
  }

  etaHEN_log("Jailbreak request from %s for PID %d",
             source ? source : "unknown", pid);

  pthread_mutex_lock(&g_jailbreak_lock);

  pid_t target_pid = pid;
  char title_id[10] = {0};
  bool has_source_title_id =
      sandbox_source_to_title_id(source, title_id, sizeof(title_id));
  etaHEN_log("Request details: source='%s', requested_pid=%d, title_id='%s'",
             source ? source : "unknown", pid,
             has_source_title_id ? title_id : "not available");

  UniquePtr<Hijacker> hijacker = nullptr;
  for (int retry = 0; retry < 300 && !g_exit_requested; retry++) {
    hijacker = Hijacker::getHijacker(target_pid);
    if (hijacker != nullptr) {
      break;
    }

    if (has_source_title_id) {
      pid_t title_pid = find_pid_by_title_id(title_id);
      if (title_pid > 0 && title_pid != target_pid) {
        etaHEN_log("Resolved %s to PID %d (requested PID %d)", title_id,
                   title_pid, pid);
        target_pid = title_pid;
      } else if (retry == 0 && title_pid <= 0) {
        etaHEN_log("Title ID %s was not visible in process list yet", title_id);
      }
    }

    if (retry == 25 || retry == 100 || retry == 200) {
      etaHEN_log("Still waiting for attachable PID. requested=%d target=%d "
                 "source='%s'",
                 pid, target_pid, source ? source : "unknown");
    }

    usleep(100 * 1000);
  }

  if (hijacker == nullptr) {
    log_process_snapshot(has_source_title_id ? title_id : nullptr, pid);
    pthread_mutex_unlock(&g_jailbreak_lock);
    etaHEN_log("Could not attach. requested_pid=%d target_pid=%d source='%s' "
               "title_id='%s'",
               pid, target_pid, source ? source : "unknown",
               has_source_title_id ? title_id : "not available");
    notify(true, "Jailbreak failed for PID %d", pid);
    return false;
  }

  char compat_title_id[10] = {0};
  if (has_source_title_id) {
    strncpy(compat_title_id, title_id, sizeof(compat_title_id) - 1);
  } else {
    get_title_id_for_pid(target_pid, compat_title_id, sizeof(compat_title_id));
  }

  hijacker->jailbreak(true);
  pthread_mutex_unlock(&g_jailbreak_lock);

  etaHEN_log("Granted jailbreak to PID %d", target_pid);
  if (is_homebrew_store_title(compat_title_id) ||
      is_homebrew_store_source(source)) {
    etaHEN_log("HB compat request detected: source='%s' title_id='%s'",
               source ? source : "unknown",
               compat_title_id[0] ? compat_title_id : "not available");
    prepare_homebrew_store_compat();
  }

  if (is_itemzflow_title(compat_title_id) || is_itemzflow_source(source)) {
    etaHEN_log("Itemzflow compat request detected: source='%s' title_id='%s'",
               source ? source : "unknown",
               compat_title_id[0] ? compat_title_id : "not available");
    prepare_itemzflow_compat();
  }

  notify(true, "App granted jailbreak");
  return true;
}

static bool handle_jailbreak_command(int sock, const Command &cmd) {
  if (cmd.magic != LEGACY_MAGIC) {
    etaHEN_log("Invalid magic: 0x%X", cmd.magic);
    reply_error(sock);
    return false;
  }

  etaHEN_log("Socket jailbreak payload source='%s'",
             cmd.msg1[0] ? cmd.msg1 : "legacy socket");

  if (!do_jailbreak((pid_t)cmd.PID, cmd.msg1[0] ? cmd.msg1 : "legacy socket")) {
    reply_error(sock);
    return false;
  }

  reply_ok(sock);
  return true;
}

static ssize_t slurp_file(const char *path, char *buf, size_t buf_size) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return -1;
  }

  ssize_t read_size = read(fd, buf, buf_size - 1);
  close(fd);
  if (read_size < 0) {
    return -1;
  }

  buf[read_size] = '\0';
  return read_size;
}

static pid_t parse_pid_from_json(const char *json) {
  const char *ptr = strstr(json, "\"PID\"");
  if (!ptr) {
    return -1;
  }

  ptr = strchr(ptr, ':');
  if (!ptr) {
    return -1;
  }

  ptr++;
  while (*ptr == ' ' || *ptr == '\t' || *ptr == '"') {
    ptr++;
  }

  pid_t pid = (pid_t)atoi(ptr);
  return pid > 0 ? pid : -1;
}

static void *run_file_request_monitor(void *) {
  char path[512];
  char buf[512];

  etaHEN_log("File request monitor started");

  while (!g_exit_requested) {
    DIR *dir = opendir(SANDBOX_BASE);
    if (!dir) {
      usleep(POLL_INTERVAL_US);
      continue;
    }

    struct dirent *entry;
    while (!g_exit_requested && (entry = readdir(dir)) != nullptr) {
      if (entry->d_name[0] == '.') {
        continue;
      }

      int written = snprintf(path, sizeof(path), "%s/%s%s", SANDBOX_BASE,
                             entry->d_name, JB_FILE_RELPATH);
      if (written <= 0 || (size_t)written >= sizeof(path)) {
        continue;
      }

      struct stat st;
      if (stat(path, &st) != 0 || st.st_size == 0) {
        continue;
      }

      ssize_t got = slurp_file(path, buf, sizeof(buf));
      if (got > 0) {
        pid_t pid = parse_pid_from_json(buf);
        if (pid > 0) {
          etaHEN_log("File request from %s for PID %d", entry->d_name, pid);
          do_jailbreak(pid, entry->d_name);
        } else {
          etaHEN_log("Could not parse PID from file request in %s: %s",
                     entry->d_name, buf);
        }
      }

      unlink(path);
    }

    closedir(dir);
    usleep(POLL_INTERVAL_US);
  }

  etaHEN_log("File request monitor stopped");
  return nullptr;
}

static void handle_client(int client) {
  Command cmd;

  while (!g_exit_requested) {
    ssize_t read_size = recv(client, &cmd, sizeof(cmd), MSG_NOSIGNAL);
    if (read_size <= 0) {
      break;
    }

    if ((size_t)read_size != sizeof(cmd)) {
      etaHEN_log("Short command read: %zd", read_size);
      reply_error(client);
      continue;
    }

    etaHEN_log("Command %d for PID %d", cmd.cmd, cmd.PID);
    switch (cmd.cmd) {
    case JAILBREAK_CMD:
      handle_jailbreak_command(client, cmd);
      break;
    case INVALID_CMD:
      reply_error(client);
      break;
    default:
      etaHEN_log("Unsupported command: %d", cmd.cmd);
      reply_error(client);
      break;
    }
  }
}

static bool run_legacy_server(void) {
  g_server_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (g_server_socket < 0) {
    notify(true, "Failed to create socket: %s", strerror(errno));
    return false;
  }

  int opt = 1;
  setsockopt(g_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  setsockopt(g_server_socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  address.sin_port = htons(LEGACY_PORT);

  if (bind(g_server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
    notify(true, "Failed to bind port %d: %s", LEGACY_PORT, strerror(errno));
    close(g_server_socket);
    g_server_socket = -1;
    return false;
  }

  if (listen(g_server_socket, 5) < 0) {
    notify(true, "Failed to listen on port %d: %s", LEGACY_PORT,
           strerror(errno));
    close(g_server_socket);
    g_server_socket = -1;
    return false;
  }

  etaHEN_log("Jailbreak socket server started on port %d", LEGACY_PORT);

  while (!g_exit_requested) {
    int client = accept(g_server_socket, nullptr, nullptr);
    if (client < 0) {
      if (!g_exit_requested) {
        etaHEN_log("accept failed: %s", strerror(errno));
      }
      continue;
    }

    etaHEN_log("Client connected");
    handle_client(client);
    close(client);
  }

  if (g_server_socket >= 0) {
    close(g_server_socket);
    g_server_socket = -1;
  }

  return true;
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  set_payload_process_name("LegacyJB.elf");

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  ensure_dir("/user");
  ensure_dir("/user/data");
  ensure_dir("/system_tmp");
  prepare_itemzflow_filesystem();

  payload_args_t *args = payload_get_args();
  if (args) {
    kernel_base = (uint64_t)args->kdata_base_addr;
  }

  int net_ret = sceNetInit();
  int netctl_ret = sceNetCtlInit();
  int usersvc_ret = sceUserServiceInitialize(NULL);
  etaHEN_log("Build: %s", LEGACY_BUILD_TAG);
  etaHEN_log("Kernel base: 0x%llX", (unsigned long long)kernel_base);
  etaHEN_log("Runtime kernel data base: 0x%llX",
             (unsigned long long)KERNEL_ADDRESS_DATA_BASE);
  etaHEN_log("Runtime offsets: allproc=0x%llX rootvnode=0x%llX",
             (unsigned long long)offsets::allproc(),
             (unsigned long long)offsets::root_vnode());
  etaHEN_log("sceNetInit: 0x%X, sceNetCtlInit: 0x%X, "
             "sceUserServiceInitialize: 0x%X",
             net_ret, netctl_ret, usersvc_ret);

  if (kernel_base == 0) {
    notify(true, "Legacy Jailbreak Server failed\nMissing kernel base");
    return 1;
  }

  static IpcCompatServer crit_ipc_server = {
      CRIT_IPC_SOC, "crit", false, &g_crit_ipc_socket};
  static IpcCompatServer util_ipc_server = {
      UTIL_IPC_SOC, "util", true, &g_util_ipc_socket};

  pthread_t crit_ipc_thread = 0;
  if (pthread_create(&crit_ipc_thread, nullptr, run_ipc_compat_server,
                     &crit_ipc_server) != 0) {
    etaHEN_log("Itemzflow compat crit IPC thread failed: %s", strerror(errno));
  }

  pthread_t util_ipc_thread = 0;
  if (pthread_create(&util_ipc_thread, nullptr, run_ipc_compat_server,
                     &util_ipc_server) != 0) {
    etaHEN_log("Itemzflow compat util IPC thread failed: %s", strerror(errno));
  }

  pthread_t dumper_monitor_thread = 0;
  if (pthread_create(&dumper_monitor_thread, nullptr, run_dumper_monitor,
                     nullptr) != 0) {
    etaHEN_log("Itemzflow dumper monitor thread failed: %s", strerror(errno));
  }

  pthread_t file_monitor_thread = 0;
  if (pthread_create(&file_monitor_thread, nullptr, run_file_request_monitor,
                     nullptr) != 0) {
    notify(true, "File monitor failed to start");
    etaHEN_log("File monitor failed to start: %s", strerror(errno));
  }

  notify(false,
         "LegacyJB ready\nSocket: %d\nFile monitor: enabled\nDev. By Phoenixx",
         LEGACY_PORT);

  bool server_ok = run_legacy_server();
  g_exit_requested = 1;

  if (file_monitor_thread != 0) {
    pthread_join(file_monitor_thread, nullptr);
  }

  if (crit_ipc_thread != 0) {
    pthread_join(crit_ipc_thread, nullptr);
  }

  if (util_ipc_thread != 0) {
    pthread_join(util_ipc_thread, nullptr);
  }

  if (dumper_monitor_thread != 0) {
    pthread_join(dumper_monitor_thread, nullptr);
  }

  return server_ok ? 0 : 1;
}
