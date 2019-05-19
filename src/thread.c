#include <Windows.h>
#include <tchar.h>
#include "include\thread.h"

int open_nt_thread_object(PCTSTR swzTarget, DWORD dwRightsRequired, PHANDLE phOut)
{
   int res = 0;
   long lID = 0;
   DWORD dwTID = 0;

   errno = 0;
   lID = _tstol(swzTarget);

   if (lID > 0 && errno == 0)
   {
      dwTID = (DWORD)lID;
   }
   else if (_tcsicmp(swzTarget, TEXT("current")) == 0)
   {
      dwTID = GetCurrentThreadId();
   }
   else
   {
      _ftprintf(stderr, TEXT(" [!] Invalid parameter: unable to parse '%s' as a thread ID\n"), swzTarget);
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }
   res = open_nt_thread_by_tid(dwTID, dwRightsRequired, phOut);

cleanup:
   return res;
}

int open_nt_thread_by_tid(DWORD dwTID, DWORD dwRightsRequired, PHANDLE phOut)
{
   int res = 0;
   HANDLE hProc = NULL;

   if (phOut == NULL || (*phOut != INVALID_HANDLE_VALUE && *phOut != NULL))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   hProc = OpenThread(dwRightsRequired, FALSE, dwTID);
   if (hProc == NULL)
   {
      res = GetLastError();
      goto cleanup;
   }

   *phOut = hProc;

cleanup:
   return res;
}

