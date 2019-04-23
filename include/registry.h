#pragma once
#include <Windows.h>

int open_regkey_by_name(PCTSTR swzRegKey, REGSAM ulDesiredAccess, PHKEY phOut);
