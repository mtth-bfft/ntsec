#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include\service.h"
#include "include\utils.h"

int open_service(PCTSTR swzName, DWORD dwRightsRequired, SC_HANDLE *phOut)
{
   int res = 0;
   SC_HANDLE hSvcMgr = NULL;
   SC_HANDLE hSvc = NULL;

   hSvcMgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
   if (hSvcMgr == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: could not connect to the service manager, code %u"), res);
      goto cleanup;
   }

   hSvc = OpenService(hSvcMgr, swzName, dwRightsRequired);
   if (hSvc == NULL)
   {
      res = GetLastError();
      goto cleanup;
   }

   *phOut = hSvc;

cleanup:
   if (hSvcMgr != NULL)
      CloseServiceHandle(hSvcMgr);
   return res;
}

int enumerate_services_with(DWORD dwDesiredAccess)
{
   int res = 0;
   SC_HANDLE hSvcMgr = NULL;
   DWORD dwSvcTypes = SERVICE_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_KERNEL_DRIVER | SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS;
   DWORD dwBufSize = 0x1000;
   DWORD dwRequiredBufSize = 0;
   ENUM_SERVICE_STATUS *pServices = safe_alloc(dwBufSize);
   DWORD dwSvcCount = 0;
   DWORD dwContext = 0;
   BOOL bContinue = TRUE;

   UNREFERENCED_PARAMETER(dwDesiredAccess);

   hSvcMgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
   if (hSvcMgr == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: could not connect to the service manager, code %u"), res);
      goto cleanup;
   }

   do
   {
      if (EnumServicesStatus(hSvcMgr, dwSvcTypes, SERVICE_STATE_ALL, pServices, dwBufSize, &dwRequiredBufSize, &dwSvcCount, &dwContext))
      {
         bContinue = FALSE;
      }
      else if (GetLastError() == ERROR_MORE_DATA)
      {
         dwBufSize = MAX(dwBufSize, dwRequiredBufSize);
         pServices = safe_realloc(pServices, dwBufSize);
      }
      else
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: EnumServicesStatus() failed with code %u"), res);
         goto cleanup;
      }
      for (DWORD i = 0; i < dwSvcCount; i++)
      {
         SC_HANDLE hSvc = NULL;
         res = open_service(pServices[i].lpServiceName, dwDesiredAccess, &hSvc);
         if (res == 0)
         {
            if (!CloseServiceHandle(hSvc))
               _ftprintf(stderr, TEXT(" [!] Error: closing service handle while enumerating failed with code %u\n"), GetLastError());
            _tprintf(TEXT("Service %s (%s)\n"), pServices[i].lpServiceName, pServices[i].lpDisplayName);
         }
         else if (res != ERROR_ACCESS_DENIED)
         {
            _ftprintf(stderr, TEXT(" [!] Warning: opening service '%s' (%s) failed with code %u while enumerating\n"), pServices[i].lpServiceName, pServices[i].lpDisplayName, res);
         }
         res = 0;
      }
   }
   while (bContinue);

cleanup:
   if (hSvcMgr != NULL)
      CloseServiceHandle(hSvcMgr);
   if (pServices != NULL)
      safe_free(pServices);
   return res;
}