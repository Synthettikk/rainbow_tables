#ifndef attack_h
#define attack_h

#include "config.h"
#include "reduction.h"

int attack(const key target_in, Chain *table, const key secret, const key round_keys[], const int m, const int n, const int t);

#endif