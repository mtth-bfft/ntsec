#include <Windows.h>
#include <tchar.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include "include\securitydescriptor.h"
#include "include\accessright.h"
#include "include\token.h"
#include "include\targets.h"
#include "include\utils.h"

int print_sid(FILE *out, PSID pSID)
{
   int res = 0;
   PWSTR swzSID = NULL;

   if (pSID == NULL)
   {
      _ftprintf(out, TEXT("NULL"));
   }
   else if (!ConvertSidToStringSidW(pSID, &swzSID))
   {
      res = GetLastError();
      _ftprintf(out, TEXT("(unknown SID, code %u)"), res);
   }
   else
   {
      _ftprintf(out, TEXT("%ws"), swzSID);
      LocalFree(swzSID);
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

   if (pSID == NULL)
   {
      _ftprintf(out, TEXT("NULL"));
      goto cleanup;
   }
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

int print_sddl(FILE *out, PSECURITY_DESCRIPTOR pSD)
{
   int res = 0;
   PTSTR swzSDDL = NULL;
   DWORD dwSDFlags = ATTRIBUTE_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;

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

int print_acl(FILE *out, target_t targetType, PACL pACL, SECURITY_DESCRIPTOR_CONTROL sdControl)
{
   int res = 0;
   ACL_SIZE_INFORMATION daclSize = { 0 };

   if (!GetAclInformation(pACL, &daclSize, sizeof(daclSize), AclSizeInformation))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: GetAclInformation(AclSizeInformation) failed with code %u\n"), res);
      goto cleanup;
   }

   _ftprintf(out, TEXT("ACL (%u ACE%s) :"), daclSize.AceCount, (daclSize.AceCount > 1 ? TEXT("s") : TEXT("")));

   if ((sdControl & SE_DACL_DEFAULTED) != 0)
      _ftprintf(out, TEXT(" (defaulted)"));
   if ((sdControl & SE_DACL_AUTO_INHERITED) != 0)
      _ftprintf(out, TEXT(" (auto inherited)"));
   if ((sdControl & SE_DACL_PROTECTED) != 0)
      _ftprintf(out, TEXT(" (protected, blocks ACE inheritance)"));

   _ftprintf(out, TEXT("\n"));

   for (DWORD aceIdx = 0; aceIdx < daclSize.AceCount; aceIdx++)
   {
      PACE_HEADER pACEHeader = NULL;
      if (!GetAce(pACL, aceIdx, (PVOID*)&pACEHeader))
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: GetAce() failed with code %u\n"), res);
         goto cleanup;
      }
      if (pACEHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
      {
         PACCESS_ALLOWED_ACE pACE = (PACCESS_ALLOWED_ACE)pACEHeader;
         PSID pTrusteeSID = (PSID)&(pACE->SidStart);

         _ftprintf(out, TEXT("    ALLOW "));
         print_sid(out, pTrusteeSID);
         _ftprintf(out, TEXT(" ("));
         print_resolved_sid(out, pTrusteeSID);
         _ftprintf(out, TEXT(") "));

         print_access_mask(out, targetType, pACE->Mask);
      }
      else if (pACEHeader->AceType == ACCESS_DENIED_ACE_TYPE)
      {
         PACCESS_DENIED_ACE pACE = (PACCESS_DENIED_ACE)pACEHeader;
         PSID pTrusteeSID = (PSID)&(pACE->SidStart);

         _ftprintf(out, TEXT("    DENY "));
         print_sid(out, pTrusteeSID);
         _ftprintf(out, TEXT(" ("));
         print_resolved_sid(out, pTrusteeSID);
         _ftprintf(out, TEXT(") "));

         print_access_mask(out, targetType, pACE->Mask);
      }
      else if (pACEHeader->AceType == SYSTEM_AUDIT_ACE_TYPE)
      {
         PSYSTEM_AUDIT_ACE pACE = (PSYSTEM_AUDIT_ACE)pACEHeader;
         PSID pAuditedSID = (PSID)&(pACE->SidStart);
         _ftprintf(out, TEXT("    AUDIT "));

         if ((pACEHeader->AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG) != 0)
            _ftprintf(out, TEXT("SUCCESS "));
         if ((pACEHeader->AceFlags & FAILED_ACCESS_ACE_FLAG) != 0)
            _ftprintf(out, TEXT("FAILURE "));

         print_sid(out, pAuditedSID);
         _ftprintf(out, TEXT(" ("));
         print_resolved_sid(out, pAuditedSID);
         _ftprintf(out, TEXT(") "));

         print_access_mask(out, targetType, pACE->Mask);
      }
      else if (pACEHeader->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
      {
         PSYSTEM_MANDATORY_LABEL_ACE pACE = (PSYSTEM_MANDATORY_LABEL_ACE)pACEHeader;
         PSID pIntegritySID = (PSID)&(pACE->SidStart);

         _ftprintf(out, TEXT("    INTEGRITY LABEL "));
         print_sid(out, pIntegritySID);
         _ftprintf(out, TEXT(" ("));
         print_resolved_sid(out, pIntegritySID);
         _ftprintf(out, TEXT(")"));

         if ((pACE->Mask & (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP)) != 0)
         {
            _ftprintf(out, TEXT(" if lower then"));
            if ((pACE->Mask & SYSTEM_MANDATORY_LABEL_NO_READ_UP) != 0)
               _ftprintf(out, TEXT(" SYSTEM_MANDATORY_LABEL_NO_READ_UP"));
            if ((pACE->Mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) != 0)
               _ftprintf(out, TEXT(" SYSTEM_MANDATORY_LABEL_NO_WRITE_UP"));
            if ((pACE->Mask & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP) != 0)
               _ftprintf(out, TEXT(" SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP"));
         }
      }
      else
      {
         _ftprintf(out, TEXT("    <unsupported ACE type %u>"), pACEHeader->AceType);
      }
      _ftprintf(out, TEXT("\n"));
   }

cleanup:
   return res;
}

int print_sd(FILE *out, target_t targetType, PSECURITY_DESCRIPTOR pSD)
{
   int res = 0;
   DWORD dwRevision = 0;
   SECURITY_DESCRIPTOR_CONTROL sdControl = 0;
   BOOL bOwnerDefaulted = FALSE;
   PSID pOwnerSID = NULL;
   BOOL bGroupDefaulted = FALSE;
   PSID pGroupSID = NULL;
   BOOL bDACLPresent = FALSE;
   PACL pDACL = NULL;
   BOOL bDACLDefaulted = FALSE;
   BOOL bSACLPresent = FALSE;
   PACL pSACL = NULL;
   BOOL bSACLDefaulted = FALSE;

   if (!GetSecurityDescriptorControl(pSD, &sdControl, &dwRevision))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: retrieving control info from security descriptor failed with code %u\n"), res);
      goto cleanup;
   }

   if (!GetSecurityDescriptorOwner(pSD, &pOwnerSID, &bOwnerDefaulted))
   {
      _ftprintf(stderr, TEXT(" [!] Warning: retrieving owner from security descriptor failed with code %u\n"), GetLastError());
   }
   else
   {
      _ftprintf(out, TEXT(" Owner: "));
      print_sid(out, pOwnerSID);
      _ftprintf(out, TEXT(" ("));
      print_resolved_sid(out, pOwnerSID);
      if (bOwnerDefaulted)
         _ftprintf(out, TEXT(") (defaulted"));
      _ftprintf(out, TEXT(")\n"));
   }

   if (!GetSecurityDescriptorGroup(pSD, &pGroupSID, &bGroupDefaulted))
   {
      _ftprintf(stderr, TEXT(" [!] Warning: retrieving group from security descriptor failed with code %u\n"), GetLastError());
   }
   else
   {
      _ftprintf(out, TEXT(" Group: "));
      print_sid(out, pGroupSID);
      _ftprintf(out, TEXT(" ("));
      print_resolved_sid(out, pGroupSID);
      if (bGroupDefaulted)
         _ftprintf(out, TEXT(") (defaulted"));
      _ftprintf(out, TEXT(")\n"));
   }

   if (!GetSecurityDescriptorDacl(pSD, &bDACLPresent, &pDACL, &bDACLDefaulted))
   {
      _ftprintf(stderr, TEXT(" [!] Warning: retrieving DACL from security descriptor failed with code %u\n"), GetLastError());
   }
   else
   {
      _ftprintf(out, TEXT(" D"));
      if (pDACL == NULL || (sdControl & SE_DACL_PRESENT) == 0)
      {
         _ftprintf(out, TEXT("ACL: NULL (full access is granted to everyone)\n"));
      }
      else
      {
         print_acl(out, targetType, pDACL, sdControl);
      }
   }

   if (!GetSecurityDescriptorSacl(pSD, &bSACLPresent, &pSACL, &bSACLDefaulted))
   {
      _ftprintf(stderr, TEXT(" [!] Warning: retrieving SACL from security descriptor failed with code %u\n"), GetLastError());
   }
   else
   {
      _ftprintf(out, TEXT(" S"));
      if (pSACL == NULL || (sdControl & SE_SACL_PRESENT) == 0)
      {
         _ftprintf(out, TEXT("ACL: NULL\n"));
      }
      else
      {
         print_acl(out, targetType, pSACL, sdControl);
      }
   }

cleanup:
   return res;
}

int print_target_sddl(FILE *out, target_t *pTargetType, PCTSTR swzTarget)
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

   res = open_target_by_typeid(swzTarget, pTargetType, dwOpenRights, &hTarget);
   if (res != 0)
   {
      _ftprintf(stderr, TEXT(" [!] Error: opening object to print its security descriptor failed with code %u\n"), res);
      goto cleanup;
   }

   dwRes = GetSecurityInfo(hTarget, SE_KERNEL_OBJECT, dwSDFlags, NULL, NULL, NULL, NULL, &pSD);
   if (dwRes != ERROR_SUCCESS)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: unable to query security descriptor (error %u)\n"), res);
      goto cleanup;
   }

   res = print_sddl(out, pSD);

cleanup:
   if (pSD != NULL)
      LocalFree(pSD);
   return res;
}

int print_target_sd(FILE *out, target_t *pTargetType, PCTSTR swzTarget)
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
         _ftprintf(stderr, TEXT(" [!] Warning: enabling SeSecurityPrivilege failed with code %u, SD will be incomplete\n"), res);
         res = 0;
      }
   }

   res = open_target_by_typeid(swzTarget, pTargetType, dwOpenRights, &hTarget);
   if (res != 0)
   {
      _ftprintf(stderr, TEXT(" [!] Error: opening object to print its SDDL failed with code %u\n"), res);
      goto cleanup;
   }

   dwRes = GetSecurityInfo(hTarget, SE_KERNEL_OBJECT, dwSDFlags, NULL, NULL, NULL, NULL, &pSD);
   if (dwRes != ERROR_SUCCESS)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: unable to query security descriptor (error %u)\n"), res);
      goto cleanup;
   }

   res = print_sd(out, *pTargetType, pSD);

cleanup:
   if (pSD != NULL)
      LocalFree(pSD);
   return res;
}
