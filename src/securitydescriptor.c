#include <Windows.h>
#include <tchar.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include "include\securitydescriptor.h"
#include "include\token.h"
#include "include\targets.h"
#include "include\utils.h"

int print_sid(FILE *out, PSID pSID)
{
   int res = 0;
   PWSTR swzSID = NULL;
   if (!ConvertSidToStringSidW(pSID, &swzSID))
   {
      res = GetLastError();
      _ftprintf(out, TEXT("(unknown SID, code %u)"), res);
   }
   else
   {
      _ftprintf(out, TEXT("%ws"), swzSID);
   }
   return res;
}

int print_resolved_sid(FILE *out, PSID pSID)
{
   int res = 0;
   DWORD dwAccountLen = 0;
   DWORD dwDomainLen = 0;
   SID_NAME_USE sidUse;
   PWSTR swzAccount = NULL;
   PWSTR swzDomain = NULL;
   if (LookupAccountSidW(NULL, pSID, NULL, &dwAccountLen, NULL, &dwDomainLen, &sidUse) ||
      GetLastError() != ERROR_INSUFFICIENT_BUFFER)
   {
      res = GetLastError();
      _ftprintf(out, TEXT("unknown SID (code %u)"), res);
      goto cleanup;
   }
   swzAccount = safe_alloc(dwAccountLen * sizeof(WCHAR));
   swzDomain = safe_alloc(dwDomainLen * sizeof(WCHAR));
   if (!LookupAccountSidW(NULL, pSID, swzAccount, &dwAccountLen, swzDomain, &dwDomainLen, &sidUse))
   {
      res = GetLastError();
      _ftprintf(out, TEXT("unknown SID (code %u)"), res);
      goto cleanup;
   }
   _ftprintf(out, TEXT("%ws\\%ws"), swzDomain, swzAccount);

cleanup:
   if (swzAccount != NULL)
      safe_free(swzAccount);
   if (swzDomain != NULL)
      safe_free(swzDomain);
   return res;
}

int print_sddl(FILE *out, PSECURITY_DESCRIPTOR pSD, DWORD dwSDFlags)
{
   int res = 0;
   PTSTR swzSDDL = NULL;

   if (!ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, dwSDFlags, &swzSDDL, NULL))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: unable to convert security descriptor to string (error %u)\n"), res);
      goto cleanup;
   }
   _ftprintf(out, TEXT("%s\n"), swzSDDL);

cleanup:
   if (swzSDDL != NULL)
      LocalFree(swzSDDL);
   return res;
}

int print_sd(FILE *out, PSECURITY_DESCRIPTOR pSD, DWORD dwSDFlags)
{
   UNREFERENCED_PARAMETER(out);
   UNREFERENCED_PARAMETER(pSD);
   UNREFERENCED_PARAMETER(dwSDFlags);
   _ftprintf(stderr, TEXT(" [!] Security descriptor printing: WIP\n"));
   return ERROR_NOT_SUPPORTED;
}

int print_target_sddl(FILE *out, target_t targetType, PCTSTR swzTarget)
{
   int res = 0;
   DWORD dwRes = 0;
   HANDLE hTarget = INVALID_HANDLE_VALUE;
   DWORD dwOpenRights = READ_CONTROL;
   DWORD dwSDFlags = ATTRIBUTE_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
   PSECURITY_DESCRIPTOR pSD = NULL;

   // Dump SACL information, only possible when privileged enough
   if (has_privilege_caller(SE_SECURITY_NAME))
   {
      res = set_privilege_caller(SE_SECURITY_NAME, SE_PRIVILEGE_ENABLED);
      if (res == 0)
      {
         dwOpenRights |= ACCESS_SYSTEM_SECURITY;
         dwSDFlags |= SACL_SECURITY_INFORMATION;
      }
      else
      {
         _ftprintf(stderr, TEXT(" [!] Warning: enabling SeSecurityPrivilege failed with code %u, SDDL will be incomplete\n"), res);
         res = 0;
      }
   }

   res = open_target_by_typeid(swzTarget, targetType, dwOpenRights, &hTarget);
   if (res != 0)
      goto cleanup;

   dwRes = GetSecurityInfo(hTarget, SE_KERNEL_OBJECT, dwSDFlags, NULL, NULL, NULL, NULL, &pSD);
   if (dwRes != ERROR_SUCCESS)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: unable to query security descriptor (error %u)\n"), res);
      goto cleanup;
   }

   res = print_sddl(out, pSD, dwSDFlags);

cleanup:
   if (pSD != NULL)
      LocalFree(pSD);
   return res;
}

int print_target_sd(FILE *out, target_t targetType, PCTSTR swzTarget)
{
   int res = 0;
   DWORD dwRes = 0;
   HANDLE hTarget = INVALID_HANDLE_VALUE;
   DWORD dwOpenRights = READ_CONTROL;
   DWORD dwSDFlags = ATTRIBUTE_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
   PSECURITY_DESCRIPTOR pSD = NULL;

   // Dump SACL information, only possible when privileged enough
   if (has_privilege_caller(SE_SECURITY_NAME))
   {
      dwOpenRights |= ACCESS_SYSTEM_SECURITY;
      dwSDFlags |= SACL_SECURITY_INFORMATION;
      set_privilege_caller(SE_SECURITY_NAME, TRUE);
   }

   res = open_target_by_typeid(swzTarget, targetType, dwOpenRights, &hTarget);
   if (res != 0)
      goto cleanup;

   dwRes = GetSecurityInfo(hTarget, SE_KERNEL_OBJECT, dwSDFlags, NULL, NULL, NULL, NULL, &pSD);
   if (dwRes != ERROR_SUCCESS)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: unable to query security descriptor (error %u)\n"), res);
      goto cleanup;
   }

   res = print_sd(out, pSD, dwSDFlags);

cleanup:
   if (pSD != NULL)
      LocalFree(pSD);
   return res;
}
