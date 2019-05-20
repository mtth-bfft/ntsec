#pragma once
#include <Windows.h>
#include "include\targets.h"

int open_nt_filterconnectionport_object(PCTSTR swzNTPath, target_t *pTargetType, DWORD dwRightsRequired, HANDLE *phOut);
