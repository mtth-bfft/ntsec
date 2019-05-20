#pragma once
#include <Windows.h>

typedef enum {
   TARGET_NONE = 0,
   TARGET_ALPC_CONNECTION_PORT,
   TARGET_DIRECTORY_OBJECT,
   TARGET_EVENT,
   TARGET_FILE,
   TARGET_FILE_DIRECTORY,
   TARGET_FILE_NAMED_PIPE,
   TARGET_FILTER_CONNECTION_PORT,
   TARGET_JOB,
   TARGET_KEYED_EVENT,
   TARGET_MEMORY_PARTITION,
   TARGET_MUTANT,
   TARGET_PROCESS,
   TARGET_REGKEY,
   TARGET_SECTION,
   TARGET_SEMAPHORE,
   TARGET_SERVICE,
   TARGET_SESSION,
   TARGET_SYMBOLIC_LINK,
   TARGET_THREAD,
   TARGET_TIMER,
   TARGET_TOKEN_PRIMARY,
   TARGET_TOKEN_IMPERSONATION,
} target_t;

int open_target_by_typeid(PCTSTR swzTarget, target_t *pTargetType, DWORD dwRightsRequired, HANDLE *phOut);
int open_target_by_typename(PCTSTR swzTarget, PCTSTR swzTypeName, SIZE_T dwTypeNameLen, DWORD dwRightsRequired, HANDLE *phOut);
int lookup_type_id(PCTSTR swzTypeName, SIZE_T dwLen, target_t* pTypeID);
