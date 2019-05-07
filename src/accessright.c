#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <sddl.h>
#include "accessright.h"

#ifndef MEMORY_PARTITION_QUERY_ACCESS
#define MEMORY_PARTITION_QUERY_ACCESS 0x0001
#endif
#ifndef MEMORY_PARTITION_MODIFY_ACCESS
#define MEMORY_PARTITION_MODIFY_ACCESS 0x0002
#endif
#ifndef MEMORY_PARTITION_ALL_ACCESS
#define MEMORY_PARTITION_ALL_ACCESS \
   (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
   MEMORY_PARTITION_QUERY_ACCESS | MEMORY_PARTITION_MODIFY_ACCESS)
#endif

enum
{
   ADS_RIGHT_DELETE = 0x10000,
   ADS_RIGHT_READ_CONTROL = 0x20000,
   ADS_RIGHT_WRITE_DAC = 0x40000,
   ADS_RIGHT_WRITE_OWNER = 0x80000,
   ADS_RIGHT_SYNCHRONIZE = 0x100000,
   ADS_RIGHT_ACCESS_SYSTEM_SECURITY = 0x1000000,
   ADS_RIGHT_GENERIC_READ = 0x80000000,
   ADS_RIGHT_GENERIC_WRITE = 0x40000000,
   ADS_RIGHT_GENERIC_EXECUTE = 0x20000000,
   ADS_RIGHT_GENERIC_ALL = 0x10000000,
   ADS_RIGHT_DS_CREATE_CHILD = 0x1,
   ADS_RIGHT_DS_DELETE_CHILD = 0x2,
   ADS_RIGHT_ACTRL_DS_LIST = 0x4,
   ADS_RIGHT_DS_SELF = 0x8,
   ADS_RIGHT_DS_READ_PROP = 0x10,
   ADS_RIGHT_DS_WRITE_PROP = 0x20,
   ADS_RIGHT_DS_DELETE_TREE = 0x40,
   ADS_RIGHT_DS_LIST_OBJECT = 0x80,
   ADS_RIGHT_DS_CONTROL_ACCESS = 0x100
}  ADS_RIGHTS_ENUM;

PCTSTR pAccessRights[][5] = {
   // Generic access rights
   { (PCTSTR) MAXIMUM_ALLOWED,                    TEXT("MAXIMUM_ALLOWED"),                    NULL,        NULL,         NULL },
   { (PCTSTR) GENERIC_READ,                       TEXT("GENERIC_READ"),                       TEXT("GR"),  NULL,         NULL },
   { (PCTSTR) GENERIC_WRITE,                      TEXT("GENERIC_WRITE"),                      TEXT("GW"),  NULL,         NULL },
   { (PCTSTR) GENERIC_EXECUTE,                    TEXT("GENERIC_EXECUTE"),                    TEXT("GE"),  NULL,         NULL },
   { (PCTSTR) GENERIC_ALL,                        TEXT("GENERIC_ALL"),                        TEXT("GA"),  NULL,         NULL },
   { (PCTSTR) ACCESS_SYSTEM_SECURITY,             TEXT("ACCESS_SYSTEM_SECURITY"),             TEXT("AS"),  NULL,         NULL },
   // Standard access rights
   { (PCTSTR) DELETE,                             TEXT("DELETE"),                             TEXT("SD"),  NULL,         NULL },
   { (PCTSTR) READ_CONTROL,                       TEXT("READ_CONTROL"),                       TEXT("SD"),  NULL,         NULL },
   { (PCTSTR) SYNCHRONIZE,                        TEXT("SYNCHRONIZE"),                        NULL,        NULL,         NULL },
   { (PCTSTR) WRITE_DAC,                          TEXT("WRITE_DAC"),                          TEXT("WD"),  NULL,         NULL },
   { (PCTSTR) WRITE_OWNER,                        TEXT("WRITE_OWNER"),                        TEXT("WO"),  NULL,         NULL },
   { (PCTSTR) STANDARD_RIGHTS_ALL,                TEXT("STANDARD_RIGHTS_ALL"),                NULL,        NULL,         NULL },
   { (PCTSTR) STANDARD_RIGHTS_EXECUTE,            TEXT("STANDARD_RIGHTS_EXECUTE"),            NULL,        NULL,         NULL },
   { (PCTSTR) STANDARD_RIGHTS_READ,               TEXT("STANDARD_RIGHTS_READ"),               NULL,        NULL,         NULL },
   { (PCTSTR) STANDARD_RIGHTS_WRITE,              TEXT("STANDARD_RIGHTS_WRITE"),              NULL,        NULL,         NULL },
   // Process specific rights
   { (PCTSTR) PROCESS_ALL_ACCESS,                 TEXT("PROCESS_ALL_ACCESS"),                 NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_CREATE_PROCESS,             TEXT("PROCESS_CREATE_PROCESS"),             NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_CREATE_THREAD,              TEXT("PROCESS_CREATE_THREAD"),              NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_DUP_HANDLE,                 TEXT("PROCESS_DUP_HANDLE"),                 NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_QUERY_INFORMATION,          TEXT("PROCESS_QUERY_INFORMATION"),          NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_QUERY_LIMITED_INFORMATION,  TEXT("PROCESS_QUERY_LIMITED_INFORMATION"),  NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_SET_INFORMATION,            TEXT("PROCESS_SET_INFORMATION"),            NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_SET_QUOTA,                  TEXT("PROCESS_SET_QUOTA"),                  NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_SUSPEND_RESUME,             TEXT("PROCESS_SUSPEND_RESUME"),             NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_TERMINATE,                  TEXT("PROCESS_TERMINATE"),                  NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_VM_OPERATION,               TEXT("PROCESS_VM_OPERATION"),               NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_VM_READ,                    TEXT("PROCESS_VM_READ"),                    NULL,        NULL,         NULL },
   { (PCTSTR) PROCESS_VM_WRITE,                   TEXT("PROCESS_VM_WRITE"),                   NULL,        NULL,         NULL },
   // Thread specific rights
   { (PCTSTR) THREAD_ALL_ACCESS,                  TEXT("THREAD_ALL_ACCESS"),                  NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_DIRECT_IMPERSONATION,        TEXT("THREAD_DIRECT_IMPERSONATION"),        NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_GET_CONTEXT,                 TEXT("THREAD_GET_CONTEXT"),                 NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_IMPERSONATE,                 TEXT("THREAD_IMPERSONATE"),                 NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_QUERY_INFORMATION,           TEXT("THREAD_QUERY_INFORMATION"),           NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_QUERY_LIMITED_INFORMATION,   TEXT("THREAD_QUERY_LIMITED_INFORMATION"),   NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_SET_CONTEXT,                 TEXT("THREAD_SET_CONTEXT"),                 NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_SET_INFORMATION,             TEXT("THREAD_SET_INFORMATION"),             NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_SET_LIMITED_INFORMATION,     TEXT("THREAD_SET_LIMITED_INFORMATION"),     NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_SET_THREAD_TOKEN,            TEXT("THREAD_SET_THREAD_TOKEN"),            NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_SUSPEND_RESUME,              TEXT("THREAD_SUSPEND_RESUME"),              NULL,        NULL,         NULL },
   { (PCTSTR) THREAD_TERMINATE,                   TEXT("THREAD_TERMINATE"),                   NULL,        NULL,         NULL },
   // Token specific rights
   { (PCTSTR) TOKEN_ADJUST_DEFAULT,               TEXT("TOKEN_ADJUST_DEFAULT"),               NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_ADJUST_GROUPS,                TEXT("TOKEN_ADJUST_GROUPS"),                NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_ADJUST_PRIVILEGES,            TEXT("TOKEN_ADJUST_PRIVILEGES"),            NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_ADJUST_SESSIONID,             TEXT("TOKEN_ADJUST_SESSIONID"),             NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_ASSIGN_PRIMARY,               TEXT("TOKEN_ASSIGN_PRIMARY"),               NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_DUPLICATE,                    TEXT("TOKEN_DUPLICATE"),                    NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_EXECUTE,                      TEXT("TOKEN_EXECUTE"),                      NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_IMPERSONATE,                  TEXT("TOKEN_IMPERSONATE"),                  NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_QUERY,                        TEXT("TOKEN_QUERY"),                        NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_QUERY_SOURCE,                 TEXT("TOKEN_QUERY_SOURCE"),                 NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_READ,                         TEXT("TOKEN_READ"),                         NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_WRITE,                        TEXT("TOKEN_WRITE"),                        NULL,        NULL,         NULL },
   { (PCTSTR) TOKEN_ALL_ACCESS,                   TEXT("TOKEN_ALL_ACCESS"),                   NULL,        NULL,         NULL },
   // Directory Services specific object rights
   { (PCTSTR) ADS_RIGHT_DS_CREATE_CHILD,          TEXT("CREATE_CHILD"),                       TEXT("CC"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_DELETE_CHILD,          TEXT("DELETE_CHILD"),                       TEXT("DC"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_ACTRL_DS_LIST,            TEXT("ACTRL_DS_LIST"),                      TEXT("LC"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_SELF,                  TEXT("SELF_WRITE"),                         TEXT("SW"),  TEXT("SELF"), NULL },
   { (PCTSTR) ADS_RIGHT_DS_READ_PROP,             TEXT("READ_PROP"),                          TEXT("RP"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_WRITE_PROP,            TEXT("WRITE_PROP"),                         TEXT("WP"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_DELETE_TREE,           TEXT("DELETE_TREE"),                        TEXT("DT"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_LIST_OBJECT,           TEXT("LIST_OBJECT"),                        TEXT("LO"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_CONTROL_ACCESS,        TEXT("CONTROL_ACCESS"),                     TEXT("CR"),  NULL,         NULL },
   // File specific rights
   { (PCTSTR) FILE_READ_DATA,                     TEXT("FILE_READ_DATA"),                     NULL,        NULL,         NULL },
   { (PCTSTR) FILE_WRITE_DATA,                    TEXT("FILE_WRITE_DATA"),                    NULL,        NULL,         NULL },
   { (PCTSTR) FILE_APPEND_DATA,                   TEXT("FILE_APPEND_DATA"),                   NULL,        NULL,         NULL },
   { (PCTSTR) FILE_READ_EA,                       TEXT("FILE_READ_EA"),                       NULL,        NULL,         NULL },
   { (PCTSTR) FILE_WRITE_EA,                      TEXT("FILE_WRITE_EA"),                      NULL,        NULL,         NULL },
   { (PCTSTR) FILE_EXECUTE,                       TEXT("FILE_EXECUTE"),                       NULL,        NULL,         NULL },
   { (PCTSTR) FILE_READ_ATTRIBUTES,               TEXT("FILE_READ_ATTRIBUTES"),               NULL,        NULL,         NULL },
   { (PCTSTR) FILE_WRITE_ATTRIBUTES,              TEXT("FILE_WRITE_ATTRIBUTES"),              NULL,        NULL,         NULL },
   { (PCTSTR) FILE_ALL_ACCESS,                    TEXT("FILE_ALL_ACCESS"),                    NULL,        NULL,         NULL },
   { (PCTSTR) FILE_GENERIC_READ,                  TEXT("FILE_GENERIC_READ"),                  NULL,        NULL,         NULL },
   { (PCTSTR) FILE_GENERIC_WRITE,                 TEXT("FILE_GENERIC_WRITE"),                 NULL,        NULL,         NULL },
   { (PCTSTR) FILE_GENERIC_EXECUTE,               TEXT("FILE_GENERIC_EXECUTE"),               NULL,        NULL,         NULL },
   // Named pipe specific rights
   { (PCTSTR) PIPE_ACCESS_DUPLEX,                 TEXT("PIPE_ACCESS_DUPLEX"),                 NULL,        NULL,         NULL },
   { (PCTSTR) PIPE_ACCESS_INBOUND,                TEXT("PIPE_ACCESS_INBOUND"),                NULL,        NULL,         NULL },
   { (PCTSTR) PIPE_ACCESS_OUTBOUND,               TEXT("PIPE_ACCESS_OUTBOUND"),               NULL,        NULL,         NULL },
   { (PCTSTR) FILE_CREATE_PIPE_INSTANCE,          TEXT("FILE_CREATE_PIPE_INSTANCE"),          NULL,        NULL,         NULL },
   // File mapping specific rights
   { (PCTSTR) FILE_MAP_ALL_ACCESS,                TEXT("FILE_MAP_ALL_ACCESS"),                NULL,        NULL,         NULL },
   { (PCTSTR) FILE_MAP_EXECUTE,                   TEXT("FILE_MAP_EXECUTE"),                   NULL,        NULL,         NULL },
   { (PCTSTR) FILE_MAP_READ,                      TEXT("FILE_MAP_READ"),                      NULL,        NULL,         NULL },
   { (PCTSTR) FILE_MAP_WRITE,                     TEXT("FILE_MAP_WRITE"),                     NULL,        NULL,         NULL },
   // Registry key specific rights
   { (PCTSTR) KEY_QUERY_VALUE,                    TEXT("KEY_QUERY_VALUE"),                    NULL,        NULL,         NULL },
   { (PCTSTR) KEY_SET_VALUE,                      TEXT("KEY_SET_VALUE"),                      NULL,        NULL,         NULL },
   { (PCTSTR) KEY_CREATE_SUB_KEY,                 TEXT("KEY_CREATE_SUB_KEY"),                 NULL,        NULL,         NULL },
   { (PCTSTR) KEY_ENUMERATE_SUB_KEYS,             TEXT("KEY_ENUMERATE_SUB_KEYS"),             NULL,        NULL,         NULL },
   { (PCTSTR) KEY_NOTIFY,                         TEXT("KEY_NOTIFY"),                         NULL,        NULL,         NULL },
   { (PCTSTR) KEY_CREATE_LINK,                    TEXT("KEY_CREATE_LINK"),                    NULL,        NULL,         NULL },
   { (PCTSTR) KEY_READ,                           TEXT("KEY_READ"),                           NULL,        NULL,         NULL },
   { (PCTSTR) KEY_WRITE,                          TEXT("KEY_WRITE"),                          NULL,        NULL,         NULL },
   { (PCTSTR) KEY_EXECUTE,                        TEXT("KEY_EXECUTE"),                        NULL,        NULL,         NULL },
   { (PCTSTR) KEY_ALL_ACCESS,                     TEXT("KEY_ALL_ACCESS"),                     NULL,        NULL,         NULL },
   // Job specific rights
   { (PCTSTR) JOB_OBJECT_ALL_ACCESS,              TEXT("JOB_OBJECT_ALL_ACCESS"),              NULL,        NULL,         NULL },
   { (PCTSTR) JOB_OBJECT_ASSIGN_PROCESS,          TEXT("JOB_OBJECT_ASSIGN_PROCESS"),          NULL,        NULL,         NULL },
   { (PCTSTR) JOB_OBJECT_QUERY,                   TEXT("JOB_OBJECT_QUERY"),                   NULL,        NULL,         NULL },
   { (PCTSTR) JOB_OBJECT_SET_ATTRIBUTES,          TEXT("JOB_OBJECT_SET_ATTRIBUTES"),          NULL,        NULL,         NULL },
   { (PCTSTR) JOB_OBJECT_SET_SECURITY_ATTRIBUTES, TEXT("JOB_OBJECT_SET_SECURITY_ATTRIBUTES"), NULL,        NULL,         NULL },
   { (PCTSTR) JOB_OBJECT_TERMINATE,               TEXT("JOB_OBJECT_TERMINATE"),               NULL,        NULL,         NULL },
   // Event specific rights
   { (PCTSTR) EVENT_ALL_ACCESS,                   TEXT("EVENT_ALL_ACCESS"),                   NULL,        NULL,         NULL },
   { (PCTSTR) EVENT_MODIFY_STATE,                 TEXT("EVENT_MODIFY_STATE"),                 NULL,        NULL,         NULL },
   // Mutex specific rights
   { (PCTSTR) MUTEX_ALL_ACCESS,                   TEXT("MUTEX_ALL_ACCESS"),                   NULL,        NULL,         NULL },
   { (PCTSTR) MUTEX_MODIFY_STATE,                 TEXT("MUTEX_MODIFY_STATE"),                 NULL,        NULL,         NULL },
   // Semaphore specific rights
   { (PCTSTR) SEMAPHORE_ALL_ACCESS,               TEXT("SEMAPHORE_ALL_ACCESS"),               NULL,        NULL,         NULL },
   { (PCTSTR) SEMAPHORE_MODIFY_STATE,             TEXT("SEMAPHORE_MODIFY_STATE"),             NULL,        NULL,         NULL },
   // Timer specific rights
   { (PCTSTR) TIMER_ALL_ACCESS,                   TEXT("TIMER_ALL_ACCESS"),                   NULL,        NULL,         NULL },
   { (PCTSTR) TIMER_MODIFY_STATE,                 TEXT("TIMER_MODIFY_STATE"),                 NULL,        NULL,         NULL },
   { (PCTSTR) TIMER_QUERY_STATE,                  TEXT("TIMER_QUERY_STATE"),                  NULL,        NULL,         NULL },
   // Memory partition specific rights
   { (PCTSTR) MEMORY_PARTITION_QUERY_ACCESS,      TEXT("MEMORY_PARTITION_QUERY_ACCESS"),      NULL,        NULL,         NULL },
   { (PCTSTR) MEMORY_PARTITION_MODIFY_ACCESS,     TEXT("MEMORY_PARTITION_MODIFY_ACCESS"),     NULL,        NULL,         NULL },
   { (PCTSTR) MEMORY_PARTITION_ALL_ACCESS,        TEXT("MEMORY_PARTITION_ALL_ACCESS"),        NULL,        NULL,         NULL },
};

static int parse_single_access_right(PTSTR swzDesiredAccess, PDWORD pdwDesiredAccess)
{
   PTSTR swzParsingEnd = NULL;
   LONG lParsedInt = -1;

   for (size_t i = 0; i < sizeof(pAccessRights) / sizeof(pAccessRights[0]); i++)
   {
      if (_tcsicmp(pAccessRights[i][1], swzDesiredAccess) == 0)
      {
         *pdwDesiredAccess = (DWORD)pAccessRights[i][0];
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