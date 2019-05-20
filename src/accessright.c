#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <sddl.h>
#include "include\accessright.h"
#include "include\targets.h"
#include "include\utils.h"

PVOID pAccessRights[][5] = {
   /****************************************** Standard access rights ******************************************/
   { (PVOID) TARGET_NONE, (PVOID) DELETE,                             TEXT("DELETE"),                             TEXT("SD"), 0 },
   { (PVOID) TARGET_NONE, (PVOID) READ_CONTROL,                       TEXT("READ_CONTROL"),                       TEXT("SD"), 0 },
   { (PVOID) TARGET_NONE, (PVOID) SYNCHRONIZE,                        TEXT("SYNCHRONIZE"),                        NULL,       0 },
   { (PVOID) TARGET_NONE, (PVOID) WRITE_DAC,                          TEXT("WRITE_DAC"),                          TEXT("WD"), 0 },
   { (PVOID) TARGET_NONE, (PVOID) WRITE_OWNER,                        TEXT("WRITE_OWNER"),                        TEXT("WO"), 0 },
   // Standard pseudo-rights aliased to a combination of the standard rights above
   { (PVOID) TARGET_NONE, (PVOID) STANDARD_RIGHTS_ALL,                TEXT("STANDARD_RIGHTS_ALL"),                NULL,       0 },
   { (PVOID) TARGET_NONE, (PVOID) STANDARD_RIGHTS_EXECUTE,            TEXT("STANDARD_RIGHTS_EXECUTE"),            NULL,       0 },
   { (PVOID) TARGET_NONE, (PVOID) STANDARD_RIGHTS_READ,               TEXT("STANDARD_RIGHTS_READ"),               NULL,       0 },
   { (PVOID) TARGET_NONE, (PVOID) STANDARD_RIGHTS_WRITE,              TEXT("STANDARD_RIGHTS_WRITE"),              NULL,       0 },
   /****************************************** Object specific rights ******************************************/
   // ALPC specific rights

   // Directory object specific rights

   // Event specific rights
   { (PVOID) TARGET_EVENT, (PVOID) EVENT_ALL_ACCESS,                   TEXT("EVENT_ALL_ACCESS"),                   NULL,        0 },
   { (PVOID) TARGET_EVENT, (PVOID) EVENT_MODIFY_STATE,                 TEXT("EVENT_MODIFY_STATE"),                 NULL,        0 },
   // File specific rights
   { (PVOID) TARGET_FILE, (PVOID) GENERIC_READ,                       TEXT("GENERIC_READ"),                       NULL,       (PVOID) FILE_GENERIC_READ },
   { (PVOID) TARGET_FILE, (PVOID) GENERIC_WRITE,                      TEXT("GENERIC_WRITE"),                      NULL,       (PVOID) FILE_GENERIC_READ },
   { (PVOID) TARGET_FILE, (PVOID) GENERIC_EXECUTE,                    TEXT("GENERIC_EXECUTE"),                    NULL,       (PVOID) FILE_GENERIC_READ },

   { (PVOID) TARGET_FILE, (PVOID) FILE_READ_DATA,                     TEXT("FILE_READ_DATA"),                     NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_WRITE_DATA,                    TEXT("FILE_WRITE_DATA"),                    NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_APPEND_DATA,                   TEXT("FILE_APPEND_DATA"),                   NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_READ_EA,                       TEXT("FILE_READ_EA"),                       NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_WRITE_EA,                      TEXT("FILE_WRITE_EA"),                      NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_EXECUTE,                       TEXT("FILE_EXECUTE"),                       NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_READ_ATTRIBUTES,               TEXT("FILE_READ_ATTRIBUTES"),               NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_WRITE_ATTRIBUTES,              TEXT("FILE_WRITE_ATTRIBUTES"),              NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_ALL_ACCESS,                    TEXT("FILE_ALL_ACCESS"),                    NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_GENERIC_READ,                  TEXT("FILE_GENERIC_READ"),                  NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_GENERIC_WRITE,                 TEXT("FILE_GENERIC_WRITE"),                 NULL,       0 },
   { (PVOID) TARGET_FILE, (PVOID) FILE_GENERIC_EXECUTE,               TEXT("FILE_GENERIC_EXECUTE"),               NULL,       0 },
   // Named pipe specific rights
   { (PVOID) TARGET_FILE_NAMED_PIPE, (PVOID) PIPE_ACCESS_INBOUND,                TEXT("PIPE_ACCESS_INBOUND"),                NULL,        0 },
   { (PVOID) TARGET_FILE_NAMED_PIPE, (PVOID) PIPE_ACCESS_OUTBOUND,               TEXT("PIPE_ACCESS_OUTBOUND"),               NULL,        0 },
   { (PVOID) TARGET_FILE_NAMED_PIPE, (PVOID) PIPE_ACCESS_DUPLEX,                 TEXT("PIPE_ACCESS_DUPLEX"),                 NULL,        0 },
   { (PVOID) TARGET_FILE_NAMED_PIPE, (PVOID) FILE_CREATE_PIPE_INSTANCE,          TEXT("FILE_CREATE_PIPE_INSTANCE"),          NULL,        0 },
   { (PVOID) TARGET_FILE_NAMED_PIPE, (PVOID) FILE_READ_EA,                       TEXT("FILE_READ_EA"),                       NULL,       0 },
   { (PVOID) TARGET_FILE_NAMED_PIPE, (PVOID) FILE_WRITE_EA,                      TEXT("FILE_WRITE_EA"),                      NULL,       0 },
   { (PVOID) TARGET_FILE_NAMED_PIPE, (PVOID) FILE_READ_ATTRIBUTES,               TEXT("FILE_READ_ATTRIBUTES"),               NULL,       0 },
   { (PVOID) TARGET_FILE_NAMED_PIPE, (PVOID) FILE_WRITE_ATTRIBUTES,              TEXT("FILE_WRITE_ATTRIBUTES"),              NULL,       0 },
   // File directory specific rights
   { (PVOID) TARGET_FILE_DIRECTORY, (PVOID) FILE_LIST_DIRECTORY,              TEXT("FILE_LIST_DIRECTORY"),              NULL,       0 },
   { (PVOID) TARGET_FILE_DIRECTORY, (PVOID) FILE_ADD_FILE,                    TEXT("FILE_ADD_FILE"),                    NULL,       0 },
   { (PVOID) TARGET_FILE_DIRECTORY, (PVOID) FILE_ADD_SUBDIRECTORY,            TEXT("FILE_ADD_SUBDIRECTORY"),            NULL,       0 },
   { (PVOID) TARGET_FILE_DIRECTORY, (PVOID) FILE_TRAVERSE,                    TEXT("FILE_TRAVERSE"),                    NULL,       0 },
   { (PVOID) TARGET_FILE_DIRECTORY, (PVOID) FILE_DELETE_CHILD,                TEXT("FILE_DELETE_CHILD"),                NULL,       0 },
   { (PVOID) TARGET_FILE_DIRECTORY, (PVOID) FILE_READ_EA,                     TEXT("FILE_READ_EA"),                       NULL,       0 },
   { (PVOID) TARGET_FILE_DIRECTORY, (PVOID) FILE_WRITE_EA,                    TEXT("FILE_WRITE_EA"),                      NULL,       0 },
   { (PVOID) TARGET_FILE_DIRECTORY, (PVOID) FILE_READ_ATTRIBUTES,             TEXT("FILE_READ_ATTRIBUTES"),               NULL,       0 },
   { (PVOID) TARGET_FILE_DIRECTORY, (PVOID) FILE_WRITE_ATTRIBUTES,            TEXT("FILE_WRITE_ATTRIBUTES"),              NULL,       0 },

   // FilterConnectionPort specific rights

   // Job specific rights
   { (PVOID) TARGET_JOB, (PVOID) JOB_OBJECT_ALL_ACCESS,              TEXT("JOB_OBJECT_ALL_ACCESS"),              NULL,        0 },
   { (PVOID) TARGET_JOB, (PVOID) JOB_OBJECT_ASSIGN_PROCESS,          TEXT("JOB_OBJECT_ASSIGN_PROCESS"),          NULL,        0 },
   { (PVOID) TARGET_JOB, (PVOID) JOB_OBJECT_QUERY,                   TEXT("JOB_OBJECT_QUERY"),                   NULL,        0 },
   { (PVOID) TARGET_JOB, (PVOID) JOB_OBJECT_SET_ATTRIBUTES,          TEXT("JOB_OBJECT_SET_ATTRIBUTES"),          NULL,        0 },
   { (PVOID) TARGET_JOB, (PVOID) JOB_OBJECT_SET_SECURITY_ATTRIBUTES, TEXT("JOB_OBJECT_SET_SECURITY_ATTRIBUTES"), NULL,        0 },
   { (PVOID) TARGET_JOB, (PVOID) JOB_OBJECT_TERMINATE,               TEXT("JOB_OBJECT_TERMINATE"),               NULL,        0 },
   // Keyed event specific rights

   // MemoryPartition specific rights
   { (PVOID) TARGET_MEMORY_PARTITION, (PVOID)MEMORY_PARTITION_QUERY_ACCESS,      TEXT("MEMORY_PARTITION_QUERY_ACCESS"),      NULL,       0 },
   { (PVOID) TARGET_MEMORY_PARTITION, (PVOID)MEMORY_PARTITION_MODIFY_ACCESS,    TEXT("MEMORY_PARTITION_MODIFY_ACCESS"),     NULL,       0 },
   { (PVOID) TARGET_MEMORY_PARTITION, (PVOID)MEMORY_PARTITION_ALL_ACCESS,       TEXT("MEMORY_PARTITION_ALL_ACCESS"),        NULL,       0 },
   // Mutant specific rights
   { (PVOID) TARGET_MUTANT, (PVOID) MUTEX_ALL_ACCESS,                   TEXT("MUTEX_ALL_ACCESS"),                   NULL,       0 },
   { (PVOID) TARGET_MUTANT, (PVOID) MUTEX_MODIFY_STATE,                 TEXT("MUTEX_MODIFY_STATE"),                 NULL,       0 },
   // Process specific rights
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_ALL_ACCESS,                 TEXT("PROCESS_ALL_ACCESS"),                 NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_CREATE_PROCESS,             TEXT("PROCESS_CREATE_PROCESS"),             NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_CREATE_THREAD,              TEXT("PROCESS_CREATE_THREAD"),              NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_DUP_HANDLE,                 TEXT("PROCESS_DUP_HANDLE"),                 NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_QUERY_INFORMATION,          TEXT("PROCESS_QUERY_INFORMATION"),          NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_QUERY_LIMITED_INFORMATION,  TEXT("PROCESS_QUERY_LIMITED_INFORMATION"),  NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_SET_INFORMATION,            TEXT("PROCESS_SET_INFORMATION"),            NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_SET_QUOTA,                  TEXT("PROCESS_SET_QUOTA"),                  NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_SUSPEND_RESUME,             TEXT("PROCESS_SUSPEND_RESUME"),             NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_TERMINATE,                  TEXT("PROCESS_TERMINATE"),                  NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_VM_OPERATION,               TEXT("PROCESS_VM_OPERATION"),               NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_VM_READ,                    TEXT("PROCESS_VM_READ"),                    NULL,        0 },
   { (PVOID) TARGET_PROCESS, (PVOID) PROCESS_VM_WRITE,                   TEXT("PROCESS_VM_WRITE"),                   NULL,        0 },
   // Registry key specific rights
   { (PVOID) TARGET_REGKEY, (PVOID) KEY_QUERY_VALUE,                    TEXT("KEY_QUERY_VALUE"),                    NULL,        0 },
   { (PVOID) TARGET_REGKEY, (PVOID) KEY_SET_VALUE,                      TEXT("KEY_SET_VALUE"),                      NULL,        0 },
   { (PVOID) TARGET_REGKEY, (PVOID) KEY_CREATE_SUB_KEY,                 TEXT("KEY_CREATE_SUB_KEY"),                 NULL,        0 },
   { (PVOID) TARGET_REGKEY, (PVOID) KEY_ENUMERATE_SUB_KEYS,             TEXT("KEY_ENUMERATE_SUB_KEYS"),             NULL,        0 },
   { (PVOID) TARGET_REGKEY, (PVOID) KEY_NOTIFY,                         TEXT("KEY_NOTIFY"),                         NULL,        0 },
   { (PVOID) TARGET_REGKEY, (PVOID) KEY_CREATE_LINK,                    TEXT("KEY_CREATE_LINK"),                    NULL,        0 },
   { (PVOID) TARGET_REGKEY, (PVOID) KEY_READ,                           TEXT("KEY_READ"),                           NULL,        0 },
   { (PVOID) TARGET_REGKEY, (PVOID) KEY_WRITE,                          TEXT("KEY_WRITE"),                          NULL,        0 },
   { (PVOID) TARGET_REGKEY, (PVOID) KEY_EXECUTE,                        TEXT("KEY_EXECUTE"),                        NULL,        0 },
   { (PVOID) TARGET_REGKEY, (PVOID) KEY_ALL_ACCESS,                     TEXT("KEY_ALL_ACCESS"),                     NULL,        0 },
   // Section specific rights
   { (PVOID) TARGET_SECTION, (PVOID)FILE_MAP_ALL_ACCESS,                TEXT("FILE_MAP_ALL_ACCESS"),                NULL,       0 },
   { (PVOID) TARGET_SECTION, (PVOID)FILE_MAP_EXECUTE,                   TEXT("FILE_MAP_EXECUTE"),                   NULL,       0 },
   { (PVOID) TARGET_SECTION, (PVOID)FILE_MAP_READ,                      TEXT("FILE_MAP_READ"),                      NULL,       0 },
   { (PVOID) TARGET_SECTION, (PVOID)FILE_MAP_WRITE,                     TEXT("FILE_MAP_WRITE"),                     NULL,       0 },
   // Semaphore specific rights
   { (PVOID) TARGET_SEMAPHORE, (PVOID)SEMAPHORE_ALL_ACCESS,               TEXT("SEMAPHORE_ALL_ACCESS"),               NULL,        0 },
   { (PVOID) TARGET_SEMAPHORE, (PVOID)SEMAPHORE_MODIFY_STATE,             TEXT("SEMAPHORE_MODIFY_STATE"),             NULL,        0 },
   // Service specific rights
   { (PVOID) TARGET_SERVICE, (PVOID)SERVICE_ALL_ACCESS,                 TEXT("SERVICE_ALL_ACCESS"),                 NULL,        0 },
   { (PVOID) TARGET_SERVICE, (PVOID)SERVICE_CHANGE_CONFIG,              TEXT("SERVICE_CHANGE_CONFIG"),              NULL,        0 },
   { (PVOID) TARGET_SERVICE, (PVOID)SERVICE_ENUMERATE_DEPENDENTS,       TEXT("SERVICE_ENUMERATE_DEPENDENTS"),       NULL,        0 },
   { (PVOID) TARGET_SERVICE, (PVOID)SERVICE_INTERROGATE,                TEXT("SERVICE_INTERROGATE"),                NULL,        0 },
   { (PVOID) TARGET_SERVICE, (PVOID)SERVICE_PAUSE_CONTINUE,             TEXT("SERVICE_PAUSE_CONTINUE"),             NULL,        0 },
   { (PVOID) TARGET_SERVICE, (PVOID)SERVICE_QUERY_CONFIG,               TEXT("SERVICE_QUERY_CONFIG"),               NULL,        0 },
   { (PVOID) TARGET_SERVICE, (PVOID)SERVICE_QUERY_STATUS,               TEXT("SERVICE_QUERY_STATUS"),               NULL,        0 },
   { (PVOID) TARGET_SERVICE, (PVOID)SERVICE_START,                      TEXT("SERVICE_START"),                      NULL,        0 },
   { (PVOID) TARGET_SERVICE, (PVOID)SERVICE_STOP,                       TEXT("SERVICE_STOP"),                       NULL,        0 },
   { (PVOID) TARGET_SERVICE, (PVOID)SERVICE_USER_DEFINED_CONTROL,       TEXT("SERVICE_USER_DEFINED_CONTROL"),       NULL,        0 },
   // Session specific rights

   // Symbolic link specific rights

   // Thread specific rights
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_ALL_ACCESS,                  TEXT("THREAD_ALL_ACCESS"),                  NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_DIRECT_IMPERSONATION,        TEXT("THREAD_DIRECT_IMPERSONATION"),        NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_GET_CONTEXT,                 TEXT("THREAD_GET_CONTEXT"),                 NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_IMPERSONATE,                 TEXT("THREAD_IMPERSONATE"),                 NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_QUERY_INFORMATION,           TEXT("THREAD_QUERY_INFORMATION"),           NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_QUERY_LIMITED_INFORMATION,   TEXT("THREAD_QUERY_LIMITED_INFORMATION"),   NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_SET_CONTEXT,                 TEXT("THREAD_SET_CONTEXT"),                 NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_SET_INFORMATION,             TEXT("THREAD_SET_INFORMATION"),             NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_SET_LIMITED_INFORMATION,     TEXT("THREAD_SET_LIMITED_INFORMATION"),     NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_SET_THREAD_TOKEN,            TEXT("THREAD_SET_THREAD_TOKEN"),            NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_SUSPEND_RESUME,              TEXT("THREAD_SUSPEND_RESUME"),              NULL,        0 },
   { (PVOID) TARGET_THREAD, (PVOID) THREAD_TERMINATE,                   TEXT("THREAD_TERMINATE"),                   NULL,        0 },
   // Timer specific rights
   { (PVOID) TARGET_TIMER,  (PVOID) TIMER_QUERY_STATE,                  TEXT("TIMER_QUERY_STATE"),                  NULL,        0 },
   { (PVOID) TARGET_TIMER,  (PVOID) TIMER_MODIFY_STATE,                 TEXT("TIMER_MODIFY_STATE"),                 NULL,        0 },
   { (PVOID) TARGET_TIMER,  (PVOID) TIMER_ALL_ACCESS,                   TEXT("TIMER_ALL_ACCESS"),                   NULL,        0 },
      // Token specific rights
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_ADJUST_DEFAULT,               TEXT("TOKEN_ADJUST_DEFAULT"),               NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_ADJUST_GROUPS,                TEXT("TOKEN_ADJUST_GROUPS"),                NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_ADJUST_PRIVILEGES,            TEXT("TOKEN_ADJUST_PRIVILEGES"),            NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_ADJUST_SESSIONID,             TEXT("TOKEN_ADJUST_SESSIONID"),             NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_ASSIGN_PRIMARY,               TEXT("TOKEN_ASSIGN_PRIMARY"),               NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_DUPLICATE,                    TEXT("TOKEN_DUPLICATE"),                    NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_EXECUTE,                      TEXT("TOKEN_EXECUTE"),                      NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_IMPERSONATE,                  TEXT("TOKEN_IMPERSONATE"),                  NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_QUERY,                        TEXT("TOKEN_QUERY"),                        NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_QUERY_SOURCE,                 TEXT("TOKEN_QUERY_SOURCE"),                 NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_READ,                         TEXT("TOKEN_READ"),                         NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_WRITE,                        TEXT("TOKEN_WRITE"),                        NULL,        0 },
   { (PVOID) TARGET_TOKEN_IMPERSONATION, (PVOID) TOKEN_ALL_ACCESS,                   TEXT("TOKEN_ALL_ACCESS"),                   NULL,        0 },
   /******************** Generic access rights, mapped for each object type to standard and/or object-specific rights ********************/
   { (PVOID) TARGET_NONE, (PVOID) MAXIMUM_ALLOWED,                     TEXT("MAXIMUM_ALLOWED"),                    NULL,        0 },
   { (PVOID) TARGET_NONE, (PVOID) GENERIC_READ,                        TEXT("GENERIC_READ"),                       TEXT("GR"),  0 },
   { (PVOID) TARGET_NONE, (PVOID) GENERIC_WRITE,                       TEXT("GENERIC_WRITE"),                      TEXT("GW"),  0 },
   { (PVOID) TARGET_NONE, (PVOID) GENERIC_EXECUTE,                     TEXT("GENERIC_EXECUTE"),                    TEXT("GE"),  0 },
   { (PVOID) TARGET_NONE, (PVOID) GENERIC_ALL,                         TEXT("GENERIC_ALL"),                        TEXT("GA"),  (PVOID)(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE) },
   { (PVOID) TARGET_NONE, (PVOID) ACCESS_SYSTEM_SECURITY,              TEXT("ACCESS_SYSTEM_SECURITY"),             TEXT("AS"),  0 },
};

int print_access_mask(FILE *out, target_t targetType, DWORD dwAccessMask)
{
   BOOL bFirst = TRUE;
   DWORD dwAccessRight = (DWORD)(1 << 31);
   BOOL bOneLine = (count_bits_set(dwAccessMask) <= 5);

   while (dwAccessRight != 0)
   {
      if ((dwAccessMask & dwAccessRight) != 0)
      {
         for (size_t i = 0; i < sizeof(pAccessRights) / sizeof(pAccessRights[0]); i++)
         {
            if ((targetType == (target_t)pAccessRights[i][0] || (target_t)pAccessRights[i][0] == TARGET_NONE) && dwAccessRight == (DWORD)pAccessRights[i][1])
            {
               if (!bOneLine)
                  _ftprintf(out, TEXT("\n        "));
               else if (!bFirst && bOneLine)
                  _ftprintf(out, TEXT(" | "));
               _ftprintf(out, TEXT("%s"), (PCTSTR)pAccessRights[i][2]);
               dwAccessMask -= dwAccessRight;
               bFirst = FALSE;
               break;
            }
         }
      }
      dwAccessRight >>= 1;
   }
   // Leftover unknown type-specific bits
   if (dwAccessMask != 0)
   {
      if (!bOneLine)
         _ftprintf(out, TEXT("\n          "));
      else if (!bFirst && bOneLine)
         _ftprintf(out, TEXT(" | "));
      _ftprintf(out, TEXT("0x%x"), dwAccessMask);
   }
   return 0;
}

static int parse_single_access_right(PTSTR swzDesiredAccess, PDWORD pdwDesiredAccess)
{
   PTSTR swzParsingEnd = NULL;
   LONG lParsedInt = -1;

   for (size_t i = 0; i < sizeof(pAccessRights) / sizeof(pAccessRights[0]); i++)
   {
      if (_tcsicmp(pAccessRights[i][2], swzDesiredAccess) == 0)
      {
         *pdwDesiredAccess = (DWORD)(SIZE_T)pAccessRights[i][1];
         return 0;
      }
   }

   lParsedInt = _tcstol(swzDesiredAccess, &swzParsingEnd, 0);
   if (lParsedInt < 0 || lParsedInt == LONG_MAX || lParsedInt == LONG_MIN || swzParsingEnd == swzDesiredAccess || lParsedInt > MAXDWORD)
      return ERROR_INVALID_PARAMETER;

   *pdwDesiredAccess = lParsedInt;
   return 0;
}

int parse_access_right(PTSTR swzDesiredAccess, PDWORD pdwDesiredAccess)
{
   int res = 0;
   PTSTR pContext = NULL;
   PTSTR swzChunk = NULL;
   DWORD dwDesiredAccess = 0;

   swzChunk = _tcstok_s(swzDesiredAccess, TEXT("|"), &pContext);
   while (swzChunk != NULL)
   {
      DWORD dwSingleRight = 0;
      res = parse_single_access_right(swzChunk, &dwSingleRight);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Unable to parse access right '%s'\n"), swzChunk);
         goto cleanup;
      }
      dwDesiredAccess |= dwSingleRight;
      swzChunk = _tcstok_s(NULL, TEXT("|"), &pContext);
   }

   *pdwDesiredAccess = dwDesiredAccess;

cleanup:
   return res;
}
