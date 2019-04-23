#pragma once
#include <Windows.h>

int print_sid(FILE *out, PSID pSID);
int print_resolved_sid(FILE *out, PSID pSID);
int get_token_info(HANDLE hToken, TOKEN_INFORMATION_CLASS infoClass, PVOID *ppResult, PDWORD pdwResultLen);
int print_sddl(PSECURITY_DESCRIPTOR pSD, DWORD dwSDFlags);
int print_sd(PSECURITY_DESCRIPTOR pSD, DWORD dwSDFlags);
int print_token(HANDLE hToken);
int set_privilege(HANDLE hToken, PCTSTR pwzPrivName, DWORD dwStatus);
int set_privilege_caller(PCTSTR pwzPrivName, DWORD dwStatus);
BOOL has_privilege_caller(PCTSTR swzPrivName);
