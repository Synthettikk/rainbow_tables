#ifndef reduction_h
#define reduction_h

#include <stdint.h>
#include <string.h>
#include "../includes/helpers.h"


// Prend une clé AES et un indice i, mélange les bits de clé à i
uint64_t mixing(const key k, unsigned long int i);

// Réduit la clé out à une clé de n bits à partir des bits mixés
void reductionN(uint64_t mixed, key out, int n);

// Prend une clé en entrée, un entier i et un nb de bits n, et mélange les bits de clé à i puis réduit la clé à n bits
void R(key k, unsigned long int i, int n);

// Génère k_0 dans l'espace réduit de n bits
void get_reduced_key(key out, unsigned long int t, int n);


// OLD

// Prend une clé AES128 en entrée et renvoie un élément réduit de 40bits
uint64_t reduction(key k, unsigned long int i);

// Prend une clé AES128 en entrée et renvoie un élément réduit de 40bits -> mixé, dépend du tour i
uint64_t reduction2(key k, unsigned long int i);

/* reduction : prend la clé complète, dérive reduced 16-bit dépendant de i */
uint16_t reduction16(const key k, unsigned long int i);

/* reduction : prend la clé complète, dérive reduced 24-bit dépendant de i */
uint32_t reduction24(const key k, unsigned long int i);

/* reduction : prend la clé complète, dérive reduced 8-bit dépendant de i */
uint32_t reduction8(const key k, unsigned long int i);

// Prend un entier de 40bits sortant de la fct de réduction et le transforme en une clé AES -> met les 5 octets puis complète avec des 0
void expand(uint64_t reduced, key out, unsigned long int i);

// Prend en entrée un uint64 (de 40bits concrètement) et l'expand en une clé de 128b -> mixe les 40b d'entrée dans un espace de 128b
void expand2(uint64_t reduced, key out, unsigned long int i);

/* expand : reconstruit les 16 octets à partir de reduced et i, inverse la tweak */
void expand24(uint32_t reduced, key out, unsigned long int i);

/* expand : reconstruit les 16 octets à partir de reduced et i, inverse la tweak */
void expand16(uint16_t reduced, key out, unsigned long int i);

/* expand : reconstruit les 16 octets à partir de reduced et i, inverse la tweak */
void expand8(uint32_t reduced, key out, unsigned long int i);

// Prend en entrée une clé AES128 et la ramène en une clé dans un espace réduit de 40bits (simple)
// void R(key k, unsigned long int i);

// Prend en entrée une clé AES128 et la ramène en une clé dans un espace réduit de 40bits (+ avancé)
void R2(key k, unsigned long int i);

// Prend en entrée une clé AES128 et la ramène en une clé dans un espace réduit de 24bits (JOUABLE)
void R24(key k, unsigned long int i);

// Prend en entrée une clé AES128 et la ramène en une clé dans un espace réduit de 16bits (pour tests)
void R16(key k, unsigned long int i);

// Prend en entrée une clé AES128 et la ramène en une clé dans un espace réduit de 8bits (pour tests)
void R8(key k, unsigned long int i);

#endif // reduction_h