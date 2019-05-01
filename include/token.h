#pragma once
#include <Windows.h>
#include "nt.h"

int get_token_info(HANDLE hToken, TOKEN_INFORMATION_CLASS infoClass, PVOID *ppResult, PDWORD pdwResultLen);
int print_token(HANDLE hToken);
int set_privilege(HANDLE hToken, PCTSTR pwzPrivName, DWORD dwStatus);
int set_privilege_caller(PCTSTR pwzPrivName, DWORD dwStatus);
BOOL has_privilege_caller(PCTSTR swzPrivName);
int get_target_token(PCTSTR swzTarget, target_t targetType, DWORD dwRightsRequired, HANDLE *phToken);
