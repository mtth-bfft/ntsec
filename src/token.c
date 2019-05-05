#include <Windows.h>
#include <tchar.h>
#include <sddl.h>
#include <stdio.h>
#include "token.h"
#include "securitydescriptor.h"
#include "nt.h"
#include "utils.h"

#define MAX_PRIVILEGE_NAME_LEN 45

static HANDLE hImpersonationToken = INVALID_HANDLE_VALUE;

BOOL is_impersonation_set_up()
{
   return hImpersonationToken != INVALID_HANDLE_VALUE;
}

BOOL is_impersonating()
{
   BOOL bRes = FALSE;
   HANDLE hToken = INVALID_HANDLE_VALUE;

   if (OpenThreadToken(GetCurrentThread(), 0, FALSE, &hToken) || OpenThreadToken(GetCurrentThread(), 0, TRUE, &hToken))
   {
      bRes = TRUE;
   }

   if (hToken != INVALID_HANDLE_VALUE)
      CloseHandle(hToken);
   return bRes;
}

int set_impersonation_token(HANDLE hToken)
{
   int res = 0;

   if (hToken == INVALID_HANDLE_VALUE || hToken == NULL)
      return ERROR_INVALID_PARAMETER;

   if (hImpersonationToken != INVALID_HANDLE_VALUE)
      CloseHandle(hImpersonationToken);

   if (!DuplicateToken(hToken, SecurityImpersonation, &hImpersonationToken))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: duplicating token for impersonation failed with code %u\n"), res);
      goto cleanup;
   }

cleanup:
   return res;
}

int start_impersonated_operation()
{
   int res = 0;
   set_privilege_caller(SE_IMPERSONATE_NAME, SE_PRIVILEGE_ENABLED);
   if (hImpersonationToken != INVALID_HANDLE_VALUE && !ImpersonateLoggedOnUser(hImpersonationToken))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: impersonation failed with code %u\n"), res);
   }
   return res;
}

int end_impersonated_operation()
{
   int res = 0;
   if (hImpersonationToken != INVALID_HANDLE_VALUE && !RevertToSelf())
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: reverting impersonation failed with code %u\n"), res);
   }
   return res;
}

static int lookup_privilege(PCTSTR swzPrivName, PLUID pLUID)
{
   int res = 0;
   TCHAR swzNormalizedPrivName[MAX_PRIVILEGE_NAME_LEN] = { 0 };

   if (_tcsnicmp(swzPrivName, TEXT("se"), 2) != 0)
      _tcscat_s(swzNormalizedPrivName, MAX_PRIVILEGE_NAME_LEN, TEXT("Se"));
   _tcscat_s(swzNormalizedPrivName, MAX_PRIVILEGE_NAME_LEN, swzPrivName);
   if (_tcslen(swzPrivName) < 9 || _tcsicmp(swzPrivName + _tcslen(swzPrivName) - 9, TEXT("privilege")) != 0)
      _tcscat_s(swzNormalizedPrivName, MAX_PRIVILEGE_NAME_LEN, TEXT("Privilege"));
   if (!LookupPrivilegeValue(NULL, swzNormalizedPrivName, pLUID))
   {
      res = ERROR_NO_SUCH_PRIVILEGE;
      _ftprintf(stderr, TEXT(" [!] Error: privilege name not recognized '%s'\n"), swzPrivName);
   }
   return res;
}

int set_privilege(HANDLE hToken, PCTSTR pwzPrivName, DWORD dwStatus)
{
   int res = 0;
   LUID luidPriv;
   DWORD dwNewPrivsSize = 0;
   PTOKEN_PRIVILEGES pNewPrivs = NULL;

   if (_tcsicmp(pwzPrivName, TEXT("*")) == 0)
   {
      res = get_token_info(hToken, TokenPrivileges, &pNewPrivs, &dwNewPrivsSize);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Could not adjust privileges because of token opening error\n"));
         goto cleanup;
      }
      for (DWORD i = 0; i < pNewPrivs->PrivilegeCount; i++)
      {
         pNewPrivs->Privileges[i].Attributes = dwStatus;
      }
      if (!AdjustTokenPrivileges(hToken, FALSE, pNewPrivs, dwNewPrivsSize, NULL, NULL))
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] AdjustTokenPrivileges() failed code %u\n"), res);
         goto cleanup;
      }
   }
   else
   {
      res = lookup_privilege(pwzPrivName, &luidPriv);
      if (res != 0)
         goto cleanup;

      dwNewPrivsSize = sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES);
      pNewPrivs = safe_alloc(dwNewPrivsSize);
      pNewPrivs->PrivilegeCount = 1;
      pNewPrivs->Privileges[0].Luid = luidPriv;
      pNewPrivs->Privileges[0].Attributes = dwStatus;
      if (!AdjustTokenPrivileges(hToken, FALSE, pNewPrivs, dwNewPrivsSize, NULL, NULL))
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] AdjustTokenPrivileges(%s) failed with code %u\n"), pwzPrivName, res);
         goto cleanup;
      }
   }

   cleanup:
   return res;
}

int set_privilege_caller(PCTSTR pwzPrivName, DWORD dwStatus)
{
   int res = 0;
   HANDLE hProcToken = INVALID_HANDLE_VALUE;

   if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcToken))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Unable to adjust privileges on self: OpenProcessToken(TOKEN_ADJUST_PRIVILEGES) failed with code %u\n"), res);
      goto cleanup;
   }
   res = set_privilege(hProcToken, pwzPrivName, dwStatus);

cleanup:
   if (hProcToken != INVALID_HANDLE_VALUE)
      CloseHandle(hProcToken);
   return res;
}

BOOL has_privilege(HANDLE hToken, PCTSTR swzPrivName)
{
   int res = 0;
   LUID luid = { 0 };
   PTOKEN_PRIVILEGES pPrivs = NULL;

   res = lookup_privilege(swzPrivName, &luid);
   if (res != 0)
      return FALSE;
   
   if (!get_token_info(hToken, TokenPrivileges, &pPrivs, NULL))
      return FALSE;

   for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++)
   {
      if (pPrivs->Privileges[i].Luid.HighPart == luid.HighPart &&
         pPrivs->Privileges[i].Luid.LowPart == luid.LowPart)
      {
         safe_free(pPrivs);
         return TRUE;
      }
   }
   safe_free(pPrivs);
   return FALSE;
}

BOOL has_privilege_caller(PCTSTR swzPrivName)
{
   HANDLE hToken = INVALID_HANDLE_VALUE;
   BOOL bRes = FALSE;

   if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken) && !OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
   {
      if (GetLastError() == ERROR_NO_TOKEN)
      {
         if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
         {
            _ftprintf(stderr, TEXT(" [!] Unable to query privileges on self: OpenProcessToken(TOKEN_QUERY) failed with code %u\n"), GetLastError());
            return FALSE;
         }
      }
      else
      {
         _ftprintf(stderr, TEXT(" [!] Error: unable to query privileges on self: OpenThreadToken(TOKEN_QUERY) failed with code %u\n"), GetLastError());
         return FALSE;
      }
   }

   bRes = has_privilege(hToken, swzPrivName);
   CloseHandle(hToken);
   return bRes;
}

BOOL has_privilege_impersonated_target(PCTSTR swzPrivName)
{
   if (hImpersonationToken == INVALID_HANDLE_VALUE)
      return has_privilege_caller(swzPrivName);
   return has_privilege(hImpersonationToken, swzPrivName);
}

int get_token_info(HANDLE hToken, TOKEN_INFORMATION_CLASS infoClass, PVOID *ppResult, PDWORD pdwResultLen)
{
   int res = 0;
   DWORD dwResultLen = 0;
   PVOID pResult = NULL;
   DWORD dwReqLen = 0;

   if (GetTokenInformation(hToken, infoClass, NULL, 0, &dwResultLen) ||
      GetLastError() != ERROR_INSUFFICIENT_BUFFER)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: GetTokenInformation(%u) failed with code %u"), infoClass, res);
      return res;
   }
   pResult = safe_alloc(dwResultLen);
   if (!GetTokenInformation(hToken, infoClass, pResult, dwResultLen, &dwReqLen))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: GetTokenInformation(%u) failed with code %u"), infoClass, res);
      goto cleanup;
   }
   if (pdwResultLen != NULL)
      *pdwResultLen = dwResultLen;
   *ppResult = pResult;

cleanup:
   if (res != 0 && pResult != NULL)
      safe_free(pResult);
   return res;
}

int print_token(HANDLE hToken)
{
   int res = 0;
   PTOKEN_TYPE pTokType = NULL;
   PDWORD pdwIsTokenRestricted = 0;
   PSECURITY_IMPERSONATION_LEVEL pImpersLevel = NULL;
   PTOKEN_USER pTokUser = NULL;
   PTOKEN_GROUPS pTokGroups = NULL;
   PTOKEN_GROUPS pTokRestrictedSids = NULL;
   PTOKEN_PRIVILEGES pTokPrivs = NULL;
   PDWORD pdwSessionID = NULL;
   PCSTR szTokenRestricted = NULL;
   PCSTR szTokenType = NULL;

   res = get_token_info(hToken, TokenType, &pTokType, NULL);
   if (res != 0)
   {
      _ftprintf(stderr, TEXT("Error: GetTokenInformation(TokenType): code %u\n"), res);
      goto cleanup;
   }
   else if (*pTokType == TokenPrimary)
   {
      szTokenType = "Primary token";
   }
   else if (*pTokType == TokenImpersonation)
   {
      res = get_token_info(hToken, TokenImpersonationLevel, &pImpersLevel, NULL);
      if (res != 0)
         _ftprintf(stderr, TEXT("Error: GetTokenInformation(TokenImpersonationLevel): code %u\n"), res);
      else if (*pImpersLevel == SecurityAnonymous)
         szTokenType = "Anonymous impersonation token";
      else if (*pImpersLevel == SecurityIdentification)
         szTokenType = "Identification impersonation token";
      else if (*pImpersLevel == SecurityImpersonation)
         szTokenType = "Full impersonation token";
      else if (*pImpersLevel == SecurityDelegation)
         szTokenType = "Full delegation impersonation token";
      if (szTokenType == NULL)
         szTokenType = "Impersonation token (unknown level)";
   }

   res = get_token_info(hToken, TokenHasRestrictions, &pdwIsTokenRestricted, NULL);
   if (res != 0)
   {
      _ftprintf(stderr, TEXT("Error: GetTokenInformation(TokenHasRestrictions): code %u\n"), res);
      goto cleanup;
   }
   if (*pdwIsTokenRestricted)
      szTokenRestricted = "Filtered ";
   else
      szTokenRestricted = "";

   printf(" [.] %s%s :\n", szTokenRestricted, szTokenType);

   res = get_token_info(hToken, TokenSessionId, &pdwSessionID, NULL);
   if (res != 0)
   {
      _ftprintf(stderr, TEXT("Error: GetTokenInformation(TokenSessionId): code %u\n"), res);
      goto cleanup;
   }
   printf(" Session ID:         0x%X\n", *pdwSessionID);
   printf(" SIDs:               ");
   res = get_token_info(hToken, TokenUser, &pTokUser, NULL);
   if (res != 0)
   {
      _ftprintf(stderr, TEXT("Error: GetTokenInformation(TokenUser): code %u\n"), res);
      goto cleanup;
   }
   print_sid(stdout, pTokUser->User.Sid);
   printf(" (");
   print_resolved_sid(stdout, pTokUser->User.Sid);
   printf(") (user)\n");

   res = get_token_info(hToken, TokenGroups, &pTokGroups, NULL);
   if (res != 0)
   {
      _ftprintf(stderr, TEXT("Error: GetTokenInformation(TokenGroups): code %u\n"), res);
      goto cleanup;
   }

   for (DWORD i = 0; i < pTokGroups->GroupCount; i++)
   {
      if (!(pTokGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID))
         continue;
      printf("                     ");
      print_sid(stdout, pTokGroups->Groups[i].Sid);
      printf(" (");
      print_resolved_sid(stdout, pTokGroups->Groups[i].Sid);
      printf(") (logon ID)");
      if (pTokGroups->Groups[i].Attributes & SE_GROUP_MANDATORY)
         printf(" (mandatory)");
      printf("\n");
   }

   for (DWORD i = 0; i < pTokGroups->GroupCount; i++)
   {
      if (!(pTokGroups->Groups[i].Attributes & SE_GROUP_ENABLED) ||
         (pTokGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID))
         continue;
      printf("                     ");
      print_sid(stdout, pTokGroups->Groups[i].Sid);
      printf(" (");
      print_resolved_sid(stdout, pTokGroups->Groups[i].Sid);
      printf(")");
      if (pTokGroups->Groups[i].Attributes & SE_GROUP_MANDATORY)
         printf(" (mandatory)");
      printf("\n");
   }

   BOOL bDenySidHeader = FALSE;
   for (DWORD i = 0; i < pTokGroups->GroupCount; i++)
   {
      if (!(pTokGroups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
         continue;
      if (!bDenySidHeader)
      {
         printf(" Deny-only SIDs:    ");
         bDenySidHeader = TRUE;
      }
      else
      {
         printf("                     ");
      }
      print_sid(stdout, pTokGroups->Groups[i].Sid);
      printf(" (");
      print_resolved_sid(stdout, pTokGroups->Groups[i].Sid);
      printf(")\n");
   }

   BOOL bRestrictedSidHeader = FALSE;
   res = get_token_info(hToken, TokenRestrictedSids, &pTokRestrictedSids, NULL);
   if (res != 0)
   {
      _ftprintf(stderr, TEXT("Error: GetTokenInformation(TokenRestrictedSids): code %u\n"), res);
      goto cleanup;
   }
   for (DWORD i = 0; i < pTokRestrictedSids->GroupCount; i++)
   {
      if (!bRestrictedSidHeader)
      {
         printf(" Restricted SIDs:       ");
         bRestrictedSidHeader = TRUE;
      }
      else
      {
         printf("                     ");
      }
      print_sid(stdout, pTokRestrictedSids->Groups[i].Sid);
      printf(" (");
      print_resolved_sid(stdout, pTokRestrictedSids->Groups[i].Sid);
      printf(")\n");
   }

   res = get_token_info(hToken, TokenPrivileges, &pTokPrivs, NULL);
   if (res != 0)
   {
      _ftprintf(stderr, TEXT("Error: GetTokenInformation(TokenPrivileges): code %u\n"), res);
      goto cleanup;
   }

   BOOL bEnabledPrivHeader = FALSE;
   for (DWORD i = 0; i < pTokPrivs->PrivilegeCount; i++)
   {
      WCHAR swzPrivName[100] = { 0 };
      DWORD dwPrivNameLen = 100;
      if (!(pTokPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
         continue;
      if (!LookupPrivilegeNameW(NULL, &(pTokPrivs->Privileges[i].Luid), swzPrivName, &dwPrivNameLen))
      {
         _ftprintf(stderr, TEXT("Error: LookupPrivilegeNameW(): code %u\n"),
         GetLastError());
         wcscpy_s(swzPrivName, sizeof(swzPrivName) / sizeof(swzPrivName[0]), L"(unknown)");
      }
      if (_wcsnicmp(L"Se", swzPrivName, 2) == 0)
         for (int j = 0; j + 2 < sizeof(swzPrivName) / sizeof(swzPrivName[0]); j++)
            swzPrivName[j] = swzPrivName[j + 2];
      if (wcslen(swzPrivName) > 9 && _wcsicmp(swzPrivName + wcslen(swzPrivName) - 9, L"privilege") == 0)
         swzPrivName[wcslen(swzPrivName) - 9] = L'\0';
      if (!bEnabledPrivHeader)
      {
         printf(" Enabled privileges: ");
         bEnabledPrivHeader = TRUE;
      }
      else
      {
         printf("                     ");
      }
      printf("%ws\n", swzPrivName);
   }

   BOOL bDisabledPrivHeader = FALSE;
   for (DWORD i = 0; i < pTokPrivs->PrivilegeCount; i++)
   {
      WCHAR swzPrivName[100] = { 0 };
      DWORD dwPrivNameLen = 100;
      if (pTokPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
         continue;
      if (!LookupPrivilegeNameW(NULL, &(pTokPrivs->Privileges[i].Luid), swzPrivName, &dwPrivNameLen))
      {
         _ftprintf(stderr, TEXT("Error: LookupPrivilegeNameW(): code %u\n"),
         GetLastError());
         wcscpy_s(swzPrivName, sizeof(swzPrivName) / sizeof(swzPrivName[0]), L"(unknown)");
      }
      if (_wcsnicmp(L"Se", swzPrivName, 2) == 0)
         for (int j = 0; j + 2 < sizeof(swzPrivName) / sizeof(swzPrivName[0]); j++)
            swzPrivName[j] = swzPrivName[j + 2];
      if (wcslen(swzPrivName) > 9 && _wcsicmp(swzPrivName + wcslen(swzPrivName) - 9, L"privilege") == 0)
         swzPrivName[wcslen(swzPrivName) - 9] = L'\0';
      if (!bDisabledPrivHeader)
      {
         printf(" Unused privileges:  ");
         bDisabledPrivHeader = TRUE;
      }
      else
      {
         printf("                     ");
      }
      printf("%ws\n", swzPrivName);
   }

   printf("\n");

cleanup:
   return res;
}

int get_target_token(PCTSTR swzTarget, target_t targetType, DWORD dwRightsRequired, HANDLE *phToken)
{
   int res = 0;
   HANDLE hTarget = INVALID_HANDLE_VALUE;

   if (targetType == TARGET_PRIMARY_TOKEN || targetType == TARGET_PROCESS)
   {
      res = open_target(swzTarget, TARGET_PROCESS, PROCESS_QUERY_INFORMATION, &hTarget);
      if (res != 0)
         goto cleanup;
      if (!OpenProcessToken(hTarget, dwRightsRequired, phToken))
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: opening process token failed with code %u\n"), res);
         goto cleanup;
      }
   }
   else if (targetType == TARGET_IMPERSONATION_TOKEN || targetType == TARGET_THREAD)
   {
      res = open_target(swzTarget, TARGET_THREAD, THREAD_QUERY_INFORMATION, &hTarget);
      if (res != 0)
         goto cleanup;
      if (!OpenThreadToken(hTarget, dwRightsRequired, TRUE, phToken))
      {
         res = GetLastError();
         if (res == ERROR_NO_TOKEN)
            _ftprintf(stderr, TEXT(" [!] Error: target thread is not impersonating, no token to open\n"));
         else
            _ftprintf(stderr, TEXT(" [!] Error: opening thread token failed with code %u\n"), res);
         goto cleanup;
      }
   }
   else
   {
      res = ERROR_INVALID_PARAMETER;
      _ftprintf(stderr, TEXT(" [!] Error: cannot open target, target selected must be a process or thread\n"));
      goto cleanup;
   }

cleanup:
   return res;
}
