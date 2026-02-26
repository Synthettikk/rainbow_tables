/*
 On part d'un clair random, on a qu'à prendre :

    static const uint8_t plaintext[16] = {
        0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d, 0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34
    };

    static const uint8_t expected_cipher[16] = {
        0x39,0x25,0x84,0x1d, 0x02,0xdc,0x09,0xfb, 0xdc,0x11,0x85,0x97, 0x19,0x6a,0x0b,0x32
    };

On a notre table contenant les couples (x0, xT) venant des chaines x0 -> H(x0) -> R0(H(x0)) = x1 -> H(x1) -> R1(H(x1)) = x2 -> ... -> x_t.
L'idée est que y peut-être (ou est si la table est suffisemment fournie) le résultat intermédiaire d'une des chaînes.
On reconstruit alors les y_k = y_k = R_k(H(...(R_{t-1}(H(y))...))) pour k entre T-1 et 0 afin de parcourir l'ensemble des 'positions' possibles de la chaine, 
c'est-à-dire l'ensemble des résultats intermédiaires possibles venant de y dans les chaînes.
Pour chaque k on regarde si la valeur y_kcorrespond à un x_T dans la table.
Si oui, on reconstitue la chaîne à partir de x_0 jusqu'à tomber sur le x_j tel que H(x_j) = y.
On a alors retrouvé l'antécédent de y par H -> x_j.

*/

#include "../includes/attack.h"
#include <stdio.h> // pour printf
#include "../includes/aes.h" // pour la fct f
#include <math.h> // pour l'exp dans le calcul de proba


double proba(int m, int n, int t){
    double prob = 1 - exp(- (double)m * (double)t / (double)(pow((double)2, (double)n)));
    return prob;
}


int attack(const key target_in, Chain *tab, const key secret, const key round_keys[], const int m, const int n, const int t) {
    uint8_t candidate[16]; /* tampon pour calculer l'endpoint candidat */
    uint8_t work[16];      /* tampon pour reconstruction */
    uint8_t prev[16];      /* clé avant f (candidat potentiel) */

    printf("T = %d M = %d N = %d \n", t, m, n);
    double prob = proba(m, n, t);
    printf("Proba optimale (sans collision) de réussite = %f \n", prob);

    for (int pos = t - 1; pos >= 0; --pos) {

        /*
         * target_in = f(k_pos) = c_pos (un chiffré).
         * Pour atteindre k_T depuis target_in :
         *   R(target_in, pos) -> k_{pos+1}
         *   f, R(pos+1)      -> k_{pos+2}
         *   ...
         *   f, R(T-1)        -> k_T
         *
         * On applique R D'ABORD, puis f+R pour les étapes suivantes.
         */
        memcpy(candidate, target_in, 16);
        R(candidate, pos, n);                          /* candidate = k_{pos+1} */
        for (int j = pos + 1; j < t; ++j) {
            f(candidate, round_keys, 10);
            R(candidate, j, n);
        }
        /* candidate devrait être k_T si master_key était à la position pos */

        /* recherche dans la table */
        for (int i = 0; i < m; ++i) {
            if (!key_equal(candidate, tab[i].end)) continue;

            // printf("Correspondance endpoint trouvée (chaîne %d, pos hypothétique %d). Reconstruction...\n", i, pos);

            /* reconstruire la chaîne depuis le début */
            memcpy(work, tab[i].start, 16);

            for (int j = 0; j < t; ++j) {
                memcpy(prev, work, 16);            /* prev = k_j */
                f(work, round_keys, 10);           /* work = f(k_j) = c_j */

                /*
                 * Comparer APRÈS f mais AVANT R :
                 * target_in est un chiffré (sortie de f), work aussi.
                 * Si work == target_in, alors f(prev) == f(master_key),
                 * donc prev est la clé cherchée (ou une collision).
                 */
                if (key_equal(work, target_in)) {
                    printf("Clé candidate trouvée dans chaîne %d à la position %d\n", i, j);
                    printf("Clé trouvée:");
                    print_key(prev);

                    /* vérification : comparer prev avec la vraie clé secrète */
                    if (key_equal(prev, secret)) { // en vrai si on a pas la clé on essaye de chiffrer avec la clé trouvée et on compare avec le chiffré target
                        printf("VERIFICATION REUSSIE : clé identique à la clé secrète !\n");
                    } else {
                        /* collision : f(prev) == f(secret) mais prev != secret */
                        printf("Collision : f(prev) == f(secret) mais clés différentes (2nd preimage).\n");
                    }
                    return 1;
                }

                R(work, j, n);                      /* work = k_{j+1} */
            }
            /* faux positif : endpoint matchait mais la clé n'est pas dans cette chaîne (collision de fin) */
            // printf("Faux positif chaîne %d (endpoint collision).\n", i);
        }
    }

    printf("Échec : clé non trouvée\n");
    return 0;
}