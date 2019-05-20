#pragma once
#include <Windows.h>
#include "include\targets.h"

int open_nt_thread_object(PCTSTR swzTarget, target_t *pTargetType, DWORD dwRightsRequired, PHANDLE phOut);
int open_nt_thread_by_tid(DWORD dwTID, DWORD dwRightsRequired, PHANDLE phOut);
