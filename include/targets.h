#pragma once
#include <Windows.h>

typedef enum {
   TARGET_NONE = 0,
   TARGET_PROCESS,
   TARGET_THREAD,
   TARGET_PRIMARY_TOKEN,
   TARGET_IMPERSONATION_TOKEN,
   TARGET_REGKEY,
   TARGET_FILE,
   TARGET_SERVICE,
   TARGET_DIRECTORY_OBJECT,
   TARGET_SYMBOLIC_LINK,
   TARGET_EVENT,
   TARGET_SEMAPHORE,
   TARGET_KEYED_EVENT,
   TARGET_MUTANT,
   TARGET_SECTION,
   TARGET_TIMER,
   TARGET_SESSION,
   TARGET_JOB,
   TARGET_PARTITION,
   TARGET_FILTER_CONNECTION_PORT,
   TARGET_ALPC_CONNECTION_PORT,
   TARGET_MEMORY_PARTITION,
} target_t;

int open_target_by_typeid(PCTSTR swzTarget, target_t targetType, DWORD dwRightsRequired, HANDLE *phOut);
int open_target_by_typename(PCTSTR swzTarget, PCTSTR swzTypeName, SIZE_T dwTypeNameLen, DWORD dwRightsRequired, HANDLE *phOut);
int lookup_type_id(PCTSTR swzTypeName, SIZE_T dwLen, target_t* pTypeID);
