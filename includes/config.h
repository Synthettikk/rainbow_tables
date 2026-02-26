// la dedans on met les parametres globaux etc
// mettre n, t, m et idem mais pour des tests
// l'idée ce serait de passer à un json apres pour faire du runtime (pouvoir changer les valeurs sans recompiler)

// include/config.h
#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "helpers.h"

// PARAMETRES

// Pour le main

#define M 1000 // nb de chaines
#define N 20 // nb de bits (taille de l'espace réduit)
#define T 1000 // longeur de chaine

// Pour les tests

#define M_test 600 // nb de chaines
#define N_test 15 // nb de bits (taille de l'espace réduit)
#define T_test 600 // longeur de chaine


// STRUCTURE TABLE

typedef struct {
    key start;
    key end;
} Chain;


#endif