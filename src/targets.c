#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include\targets.h"
#include "include\nt.h"
#include "include\alpc.h"
#include "include\directory.h"
#include "include\event.h"
#include "include\file.h"
#include "include\filterconnectionport.h"
#include "include\job.h"
#include "include\keyedevent.h"
#include "include\memorypartition.h"
#include "include\mutant.h"
#include "include\process.h"
#include "include\registry.h"
#include "include\section.h"
#include "include\semaphore.h"
#include "include\service.h"
#include "include\session.h"
#include "include\symboliclink.h"
#include "include\thread.h"
#include "include\timer.h"
#include "include\token.h"

typedef int(*nt_object_open_t)(PCTSTR swzNTPath, target_t *pTargetType, DWORD dwRightsRequired, PHANDLE phOut);

static PVOID supported_targets[][6] = {
   // Numeric enum identifier               NT object name                User-friendly name                     Commandline         Short command    Open callback
   { (PVOID) TARGET_ALPC_CONNECTION_PORT,   TEXT("ALPC Port"),            TEXT("ALPC connection port"),          TEXT("alpc"),       TEXT("a"),       (PVOID)&open_nt_alpcconnectionport_object },
   { (PVOID) TARGET_DIRECTORY_OBJECT,       TEXT("Directory"),            TEXT("NT object directory"),           TEXT("directory"),  TEXT("d"),       (PVOID)&open_nt_directory_object },
   { (PVOID) TARGET_EVENT,                  TEXT("Event"),                TEXT("event object"),                  TEXT("event"),      TEXT("e"),       (PVOID)&open_nt_event_object },
   { (PVOID) TARGET_FILE,                   NULL,                         TEXT("file object"),                   TEXT("file"),       TEXT("f"),       (PVOID)&open_nt_file_object },
   { (PVOID) TARGET_FILE_DIRECTORY,         NULL,                         TEXT("file directory object"),         NULL,               NULL,            (PVOID)&open_nt_file_object },
   { (PVOID) TARGET_FILE_NAMED_PIPE,        NULL,                         TEXT("named pipe"),                    TEXT("namedpipe"),  NULL,            (PVOID)&open_nt_file_object },
   { (PVOID) TARGET_FILTER_CONNECTION_PORT, TEXT("FilterConnectionPort"), TEXT("minifilter communication port"), TEXT("fltport"),    NULL,            (PVOID)&open_nt_filterconnectionport_object },
   { (PVOID) TARGET_JOB,                    TEXT("Job"),                  TEXT("job object"),                    TEXT("job"),        TEXT("j"),       (PVOID)&open_nt_job_object },
   { (PVOID) TARGET_KEYED_EVENT,            TEXT("Keyed Event"),          TEXT("keyed event object"),            TEXT("keyedevent"), NULL,            (PVOID)&open_nt_keyedevent_object },
   { (PVOID) TARGET_MEMORY_PARTITION,       TEXT("Partition"),            TEXT("memory partition object"),       TEXT("partition"),  NULL,            (PVOID)&open_nt_partition_object },
   { (PVOID) TARGET_MUTANT,                 TEXT("Mutant"),               TEXT("mutant object"),                 TEXT("mutant"),     TEXT("m"),       (PVOID)&open_nt_mutant_object },
   { (PVOID) TARGET_PROCESS,                NULL,                         TEXT("process object"),                TEXT("process"),    TEXT("p"),       (PVOID)&open_nt_process_object },
   { (PVOID) TARGET_REGKEY,                 TEXT("Registry"),             TEXT("registry key object"),           TEXT("regkey"),     TEXT("r"),       (PVOID)&open_nt_key_object },
   { (PVOID) TARGET_SECTION,                TEXT("Section"),              TEXT("section object"),                TEXT("section"),    NULL,            (PVOID)&open_nt_section_object },
   { (PVOID) TARGET_SEMAPHORE,              TEXT("Semaphore"),            TEXT("semaphore object"),              TEXT("semaphore"),  NULL,            (PVOID)&open_nt_semaphore_object },
   { (PVOID) TARGET_SERVICE,                TEXT("Service"),              TEXT("Win32 service"),                 TEXT("service"),    TEXT("s"),       (PVOID)&open_service },
   { (PVOID) TARGET_SESSION,                TEXT("Session"),              TEXT("session object"),                TEXT("session"),    NULL,            (PVOID)&open_nt_session_object },
   { (PVOID) TARGET_SYMBOLIC_LINK,          TEXT("Symbolic Link"),        TEXT("symbolic link object"),          TEXT("symlink"),    NULL,            (PVOID)&open_nt_symbolic_link_object },
   { (PVOID) TARGET_THREAD,                 TEXT("Thread"),               TEXT("thread object"),                 TEXT("thread"),     TEXT("t"),       (PVOID)&open_nt_thread_object },
   { (PVOID) TARGET_TIMER,                  TEXT("Timer"),                TEXT("timer object"),                  TEXT("timer"),      NULL,            (PVOID)&open_nt_timer_object },
   { (PVOID) TARGET_TOKEN_PRIMARY,          NULL,                         TEXT("primary token"),                 NULL,               NULL,            (PVOID)&open_nt_primary_token },
   { (PVOID) TARGET_TOKEN_IMPERSONATION,    NULL,                         TEXT("impersonation token"),           NULL,               NULL,            (PVOID)&open_nt_impersonation_token },
};

int open_target_by_typeid(PCTSTR swzTarget, target_t *pTargetType, DWORD dwRightsRequired, HANDLE *phOut)
{
   if (pTargetType == NULL || phOut == NULL || (*phOut != INVALID_HANDLE_VALUE && *phOut != NULL))
      return ERROR_INVALID_PARAMETER;

   for (SIZE_T i = 0; i < sizeof(supported_targets) / sizeof(supported_targets[0]); i++)
   {
      if ((target_t)supported_targets[i][0] == *pTargetType)
      {
         nt_object_open_t pOpenFunc = (nt_object_open_t)supported_targets[i][5];
         return pOpenFunc(swzTarget, pTargetType, dwRightsRequired, phOut);
      }
   }
   _ftprintf(stderr, TEXT(" [!] Error: unsupported target type %u\n"), *pTargetType);
   return ERROR_NOT_SUPPORTED;
}

int lookup_type_id(PCTSTR swzTypeName, SIZE_T dwLen, target_t* pTypeID)
{
   if (swzTypeName == NULL || pTypeID == NULL)
      return ERROR_INVALID_PARAMETER;
   for (SIZE_T i = 0; i < sizeof(supported_targets) / sizeof(supported_targets[0]); i++)
   {
      if (_tcsnicmp(supported_targets[i][1], swzTypeName, dwLen) == 0)
      {
         *pTypeID = (target_t)supported_targets[i][0];
         return 0;
      }
   }
   _ftprintf(stderr, TEXT(" [!] Error: could not resolve unsupported type name %s\n"), swzTypeName);
   return ERROR_NOT_SUPPORTED;
}

int open_target_by_typename(PCTSTR swzTarget, PCTSTR swzTypeName, SIZE_T dwTypeNameLen, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   target_t typeID = TARGET_NONE;

   res = lookup_type_id(swzTypeName, dwTypeNameLen, &typeID);
   if (res != 0)
      goto cleanup;

   res = open_target_by_typeid(swzTarget, &typeID, dwRightsRequired, phOut);

cleanup:
   return res;
}