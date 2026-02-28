// La première chose que l'on veut faire c'est une fonction qui mappe toute clé de AES 128 vers une clé de N bits
// Ce sera la fonction de réduction R pour notre AES

/* PRINCIPE : On reçoit une clé (un tableau de 16 octets) qui est le résultat d'un chiffrement AES. En fonction d'un indice i 
(la colonne dans la table arc-en-ciel), on veut ramener cette clé en un nombre contenu dans N bits (40 ou 24 ou 16 bits etc)
avec les fonctions "mixing", puis on ramène ce nombre à un tableau de 16 octets avec n/8 octets remplis et le reste à 0 
avec la fonction reductionN. 
La réduction à n bits se fait donc en deux phases : mixing puis reduction.
Lors de la réduction on passe de 16 à k <= 16 octets donc on perd de l'information, c'est normal 

Pour s'assurer que les fonctions de réductions Rn fonctionnent, on peut vérifier qu'à partir de 16 octets on obtient bien que les 16 - k derniers octets 
sont nuls, et que le résultat change en fonction de l'indice i.
Attention : ici la fonction Rn n'est pas une projection linéaire (on a pas Rn o Rn = Rn) à cause du tweak qui mélange les octets de la clé de départ dans l'arrivée.
bien que cela soit une projection de l'espace à 16 dans l'espace à k octets. */ 

// C'est la fonction de réduction (et le paramètre n donné) qui fixe la taille de l'espace réduit.


#include "../includes/reduction.h"
#include <stdlib.h> // pour rand()
#include <stdio.h> // for printf
// #include "../includes/config.h"

const uint8_t MASK8 = 0xFFu; 
const uint16_t MASK16 = 0xFFFFu;
const uint32_t MASK24 = (1U << 24) - 1U;    // 0x00FFFFFF
const uint64_t MASK40 = ((1ULL<<40) - 1ULL);
const uint64_t MASK64 = 0xFFFFFFFFFFFFFFFFULL;

// Crée un uint_t 64 dépendant de i (va servir pour mixer)
static uint64_t derive_tweak64(unsigned long int i){
    uint64_t s = (uint64_t)i + 0x9e3779b97f4a7c15ULL; /* constante de Knuth étendue 64-bit */
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    uint64_t t = s ^ (s << 32) ^ (s >> 33);
    return t;
}

// Prend une clé AES et un indice i, mélange les bits de clé à i
uint64_t mixing(const key k, unsigned long int i){
    // Phase de mélange dépendant de i
    uint64_t r =
        ((uint64_t)k[0] << 56) |
        ((uint64_t)k[1] << 48) |
        ((uint64_t)k[2] << 40) |
        ((uint64_t)k[3] << 32) |
        ((uint64_t)k[4] << 24) |
        ((uint64_t)k[5] << 16) |
        ((uint64_t)k[6] << 8)  |
        ((uint64_t)k[7]);
    uint64_t tweak = derive_tweak64(i);

    return (r ^ tweak) & MASK64;
}

// Réduit la clé out à une clé de n bits à partir des bits mixés
void reductionN(uint64_t mixed, key out, int n){
    if(n > 64){
        n = 64;
        printf("Attention : la réduction est prévue pour se faire sur 0 <= n <= 64 bits ; n ramené à 64.");
    }
    if (n < 0){
        n = 0;
        printf("Attention : la réduction est prévue pour se faire sur 0 <= n <= 64 ; n ramené à 0.");
    }
    uint64_t mask = (n >= 64) ? ~0ULL : ((1ULL << n) - 1ULL); // si n >= 64 on met le masque à ~0 (pour que ca modifie pas mixed)
    // masque mixed pour qu'il ait n bits -> les n bits de poids faible sont gardés, les autres passent à 0
    mixed &= mask;
    int k = (n + 7) / 8; // ceil(n/8)
    for(int i = 0; i < k; i++){
        out[i] = (uint8_t)((mixed >> 8 * i) & MASK8); // masquer avec mask8 recupere les 8 bits de poids faible (little endian)
        // out[0] = octet de poids faible de mixed, out[1] = octet d'apres, etc
    }
    memset(out + k, 0, 16 - k); // 16 ici c'est le nb d'ocets de la clé
}

// Prend une clé en entrée, un entier i et un nb de bits n, et mélange les bits de clé à i puis réduit la clé à n bits
void R(key k, unsigned long int i, int n){
    uint64_t mixed = mixing(k, i);
    reductionN(mixed, k, n);
}

// Génère k_0 dans l'espace réduit de n bits
void get_reduced_key(key out, unsigned long int t, int n){
    for (int i = 0; i < 16; ++i) out[i] = rand() & 0xFF; // pas crypto sûr mais pas besoin ici
    R(out, t, n); // ramène la clé dans l'espace restreint
}


// OLD (testé et fonctionne mais refait au dessus donc inutile)


// Prend une clé AES128 en entrée et renvoie un élément réduit de 40bits -> simple, dépend pas du tour i
uint64_t reduction(key k, unsigned long int i){
    (void)i; // si expand n'utilise pas i
    uint64_t r = ((uint64_t)k[0] << 32) |
                 ((uint64_t)k[1] << 24) |
                 ((uint64_t)k[2] << 16) |
                 ((uint64_t)k[3] << 8)  |
                 ((uint64_t)k[4]);
    return r & MASK40;
}


void expand(uint64_t reduced, key out, unsigned long int i){
    (void)i; // si expand n'utilise pas i
    out[0] = (reduced >> 32) & MASK8; // met les 8 premiers bits dans out[0]
    out[1] = (reduced >> 24) & MASK8;
    out[2] = (reduced >> 16) & MASK8;
    out[3] = (reduced >> 8)  & MASK8;
    out[4] = reduced & MASK8;
    memset(out+5, 0, 11); // complète les 11 derniers octets avec des 0
}


/* dérive un tweak 40-bit à partir de i (on retourne 64-bit mais on n'utilise que 40 bits) */
static uint64_t derive_tweak(unsigned long int i){
    /* exemple simple : generateur xorshift-ish puis répéter pour 40 bits */
    uint64_t s = (uint64_t)i + 0x9e3779b97f4a7c15ULL; /* constante de Fibonacci */
    /* 3 tours xorshift pour diffuser i */
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    /* étendre/compléter bytes en répétant le pattern */
    uint64_t t = s ^ (s << 24) ^ (s >> 16);
    return t & MASK40;
}

/* reduction : prend la clé complète, dérive reduced 40-bit dépendant de i */
uint64_t reduction2(key k, unsigned long int i){
    /* compose 40-bit à partir de k[0..4] comme avant */
    uint64_t r = ((uint64_t)k[0] << 32) |
                 ((uint64_t)k[1] << 24) |
                 ((uint64_t)k[2] << 16) |
                 ((uint64_t)k[3] << 8)  |
                 ((uint64_t)k[4]);
    uint64_t tweak = derive_tweak(i);
    return (r ^ tweak) & MASK40;
}

/* expand : reconstruit les 16 octets à partir de reduced (PAS de tweak inverse) */
void expand2(uint64_t reduced, key out, unsigned long int i){
    (void)i;
    out[0] = (reduced >> 32) & MASK8;
    out[1] = (reduced >> 24) & MASK8;
    out[2] = (reduced >> 16) & MASK8;
    out[3] = (reduced >> 8)  & MASK8;
    out[4] = reduced & MASK8;
    memset(out+5, 0, 11);
}

// LA MEME MAIS POUR 24 BITS

/* dérive un tweak 24-bit à partir de i (retourne 32-bit mais on n'utilise que 24 bits) */
static uint32_t derive_tweak24(unsigned long int i){
    uint32_t s = (uint32_t)i + 0x9e3779b9U; /* constante de Fibonacci tronquée */
    /* 3 tours xorshift pour diffuser i */
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    /* étendre/compléter bytes en répétant le pattern */
    uint32_t t = s ^ (s << 8) ^ (s >> 16);
    return t & MASK24;
}

/* reduction : prend la clé complète, dérive reduced 24-bit dépendant de i */
uint32_t reduction24(const key k, unsigned long int i){
    uint32_t r = ((uint32_t)k[0] << 16) |
                 ((uint32_t)k[1] << 8)  |
                 ((uint32_t)k[2]);
    uint32_t tweak = derive_tweak24(i);
    return (r ^ tweak) & MASK24;
}

/* expand : reconstruit les 16 octets à partir de reduced (PAS de tweak inverse) */
void expand24(uint32_t reduced, key out, unsigned long int i){
    (void)i;
    out[0] = (reduced >> 16) & MASK8;
    out[1] = (reduced >> 8) & MASK8;
    out[2] = reduced & MASK8;
    memset(out+3, 0, 13);
}

// LA MEME POUR 16 BITS 

/* dérive un tweak 16-bit à partir de i (retourne 32-bit mais on n'utilise que 16 bits) */
static uint32_t derive_tweak16(unsigned long int i){
    uint32_t s = (uint32_t)i + 0x9e3779b9U;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    uint32_t t = s ^ (s << 8) ^ (s >> 16);
    return t & MASK16;
}

/* reduction : prend la clé complète, dérive reduced 16-bit dépendant de i */
uint16_t reduction16(const key k, unsigned long int i){
    uint32_t r = ((uint32_t)k[0] << 8) |
                 ((uint32_t)k[1]);
    uint32_t tweak = derive_tweak16(i);
    return (uint16_t)((r ^ tweak) & MASK16);
}

/* expand : reconstruit les 16 octets à partir de reduced (PAS de tweak inverse, sinon R16 ne dépend plus de i) */
void expand16(uint16_t reduced, key out, unsigned long int i){
    (void)i;
    out[0] = (reduced >> 8) & MASK8;
    out[1] = reduced & MASK8;
    memset(out+2, 0, 14); /* reste des 16 octets */
}

// LA MEME POUR 8 BITS

/* dérive un tweak 8-bit à partir de i (retourne 32-bit mais on n'utilise que 8 bits) */
static uint32_t derive_tweak8(unsigned long int i){
    uint32_t s = (uint32_t)i + 0x9e3779b9U;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    uint32_t t = s ^ (s << 8) ^ (s >> 16);
    return t & MASK8;
}

/* reduction : prend la clé complète, dérive reduced 8-bit dépendant de i */
uint32_t reduction8(const key k, unsigned long int i){
    uint32_t r = (uint32_t)k[0]; /* seul le premier octet est utilisé */
    uint32_t tweak = derive_tweak8(i);
    return (r ^ tweak) & MASK8;
}

/* expand : reconstruit les 16 octets à partir de reduced (PAS de tweak inverse) */
void expand8(uint32_t reduced, key out, unsigned long int i){
    (void)i;
    out[0] = reduced & MASK8;
    memset(out+1, 0, 15);
}

// Prend en entrée une clé AES128 et la ramène en une clé dans un espace réduit de 40bits (simple)
// void R(key k, unsigned long int i){
//    uint64_t reduced = reduction(k, i);
//    expand(reduced, k, i); // modifie la clé d'entrée
// }

// Prend en entrée une clé AES128 et la ramène en une clé dans un espace réduit de 40bits (+ avancé)
void R2(key k, unsigned long int i){
    uint64_t reduced = reduction2(k, i);
    expand2(reduced, k, i); // modifie la clé d'entrée
}

// Prend en entrée une clé AES128 et la ramène en une clé dans un espace réduit de 24bits (JOUABLE)
void R24(key k, unsigned long int i){
    uint32_t reduced = reduction24(k, i);
    expand24(reduced, k, i); // modifie la clé d'entrée
}

// Prend en entrée une clé AES128 et la ramène en une clé dans un espace réduit de 16bits (pour tests)
void R16(key k, unsigned long int i){
    uint32_t reduced = reduction16(k, i);
    expand16(reduced, k, i); // modifie la clé d'entrée
}

// Prend en entrée une clé AES128 et la ramène en une clé dans un espace réduit de 8bits (pour tests)
void R8(key k, unsigned long int i){
    uint32_t reduced = reduction8(k, i);
    expand8(reduced, k, i); // modifie la clé d'entrée
}
