#pragma once
#include <Windows.h>
#include <stdio.h>
#include "nt.h"

int print_sid(FILE *out, PSID pSID);
int print_resolved_sid(FILE *out, PSID pSID);
int print_sddl(FILE *out, PSECURITY_DESCRIPTOR pSD);
int print_sd(FILE *out, target_t targetType, PSECURITY_DESCRIPTOR pSD);
int print_target_sddl(FILE *out, target_t *pTargetType, PCTSTR swzTarget);
int print_target_sd(FILE *out, target_t *pTargetType, PCTSTR swzTarget);
