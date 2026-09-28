/* Copyright (C) 2025 etaHEN / LightningMods */

#pragma once

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/_iovec.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/thr.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <msg.hpp>
#include <ps5/payload.h>

typedef struct {
  int32_t type;
  int32_t req_id;
  int32_t priority;
  int32_t msg_id;
  int32_t target_id;
  int32_t user_id;
  int32_t unk1;
  int32_t unk2;
  int32_t app_id;
  int32_t error_num;
  int32_t unk3;
  char use_icon_image_uri;
  char message[1024];
  char uri[1024];
  char unkstr[1024];
} OrbisNotificationRequest;

extern "C" int sceKernelSendNotificationRequest(
    int32_t device, OrbisNotificationRequest *req, size_t size,
    int32_t blocking);
extern "C" int sceNetInit(void);
extern "C" int sceNetCtlInit(void);
extern "C" int sceUserServiceInitialize(const void *params);
