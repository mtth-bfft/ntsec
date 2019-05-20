#pragma once
#include <Windows.h>
#include <subauth.h> // forced inside every utils-using file because of UNICODE_STRING

#ifndef MIN
#define MIN(x,y) ((x)<(y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x,y) ((x)<(y) ? (y) : (x))
#endif

PVOID safe_alloc(SIZE_T dwBytes);
PVOID safe_realloc(PVOID pBuffer, SIZE_T dwBytes);
VOID safe_free(PVOID pBuffer);
PVOID safe_dup(const VOID *pBuffer, SIZE_T dwBytes);
PTSTR safe_strdup(PCTSTR swzIn);
BOOL str_starts_with(PCTSTR swzFull, PCTSTR swzPrefix);
UNICODE_STRING* string_to_unicode(PCTSTR swzIn);
PTSTR unicode_to_string(PUNICODE_STRING pIn);
PWSTR string_to_wide(PCTSTR swzIn);
VOID basedir(PTSTR swzPath);
SIZE_T count_bits_set(SIZE_T dwBitField);
