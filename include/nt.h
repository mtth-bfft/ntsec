#pragma once
#include <Windows.h>
#include <subauth.h>

typedef enum {
   TARGET_NONE = 0,
   TARGET_PROCESS,
   TARGET_THREAD,
   TARGET_PRIMARY_TOKEN,
   TARGET_IMPERSONATION_TOKEN,
   TARGET_REGKEY,
   TARGET_FILE,
   TARGET_KERNEL_OBJECT,
} target_t;

int resolve_imports();
int open_target(PCTSTR swzTarget, target_t targetType, DWORD dwRightsRequired, HANDLE *phOut);
int open_kernel_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int do_show_sd(target_t targetType, PCTSTR swzTarget, BOOL bVerbose);
