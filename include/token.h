#pragma once
#include <Windows.h>
#include "include\targets.h"

BOOL is_impersonation_set_up();
BOOL is_impersonating();
int set_impersonation_token(HANDLE hToken);
int start_impersonated_operation();
int end_impersonated_operation();
int set_privilege(HANDLE hToken, PCTSTR pwzPrivName, DWORD dwStatus);
int set_privilege_caller(PCTSTR pwzPrivName, DWORD dwStatus);
BOOL has_privilege(HANDLE hToken, PCTSTR swzPrivName);
BOOL has_privilege_caller(PCTSTR swzPrivName);
BOOL has_privilege_impersonated_target(PCTSTR swzPrivName);
int get_token_info(HANDLE hToken, TOKEN_INFORMATION_CLASS infoClass, PVOID *ppResult, PDWORD pdwResultLen);
int open_nt_primary_token(PCTSTR swzTarget, DWORD dwRightsRequired, PHANDLE phOut);
int open_nt_impersonation_token(PCTSTR swzTarget, DWORD dwRightsRequired, PHANDLE phOut);
int print_token(HANDLE hToken);
int get_target_token(PCTSTR swzTarget, target_t targetType, DWORD dwRightsRequired, HANDLE *phToken);
