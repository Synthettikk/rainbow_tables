// Pour gérer en runtime les paramètres

#include "../includes/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// valeurs par défaut
int N = 20;
int M = 1000;
int T = 1000;

int N_test = 15;
int M_test = 600;
int T_test = 600;


static void trim(char *s) {
    char *end;
    while (*s == ' ' || *s == '\t') s++;
    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t')) *end-- = '\0';
}

bool config_load(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return false;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0' || *p == '\n' || *p == '\r') continue;
        char *nl = strpbrk(p, "\r\n");
        if (nl) *nl = '\0';
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p;
        char *val = eq + 1;
        trim(key);
        trim(val);
        int v = atoi(val);
        if (strcmp(key, "N") == 0) N = v;
        else if (strcmp(key, "M") == 0) M = v;
        else if (strcmp(key, "T") == 0) T = v;
        else if (strcmp(key, "N_test") == 0) N_test = v;
        else if (strcmp(key, "M_test") == 0) M_test = v;
        else if (strcmp(key, "T_test") == 0) T_test = v;
    }
    fclose(f);
    return true;
}