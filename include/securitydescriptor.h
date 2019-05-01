#pragma once
#include <Windows.h>
#include <stdio.h>
#include "nt.h"

int print_sid(FILE *out, PSID pSID);
int print_resolved_sid(FILE *out, PSID pSID);
int print_sddl(PSECURITY_DESCRIPTOR pSD, DWORD dwSDFlags);
int print_sd(PSECURITY_DESCRIPTOR pSD, DWORD dwSDFlags);
int print_target_sd(target_t targetType, PCTSTR swzTarget, BOOL bVerbose);
