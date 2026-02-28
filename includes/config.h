// la dedans on met les parametres globaux etc
// mettre n, t, m et idem mais pour des tests
// l'idée est de faire un cfg pour faire du runtime (pouvoir changer les valeurs sans recompiler)

// include/config.h
#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "helpers.h"

// PARAMETRES

// Pour le main

extern int N; // nb de bits (taille de l'espace réduit)
extern int M; // nb de chaînes
extern int T; // longueur des chaînes

// Pour les tests

extern int N_test; // nb de bits (taille de l'espace réduit)
extern int M_test; // nb de chaînes
extern int T_test; // longueur des chaînes

// va chercher en runtime les valeurs N, M, T et celles de tests
bool config_load(const char *filename);


// STRUCTURE TABLE

typedef struct {
    key start;
    key end;
} Chain;


#endif