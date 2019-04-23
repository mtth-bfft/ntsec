#pragma once
#include <Windows.h>

PVOID safe_alloc(SIZE_T dwBytes);
PVOID safe_realloc(PVOID pBuffer, SIZE_T dwBytes);
VOID safe_free(PVOID pBuffer);
PVOID safe_dup(const VOID *pBuffer, SIZE_T dwBytes);
PTSTR safe_strdup(PCTSTR swzIn);
BOOL str_starts_with(PCTSTR swzFull, PCTSTR swzPrefix);
