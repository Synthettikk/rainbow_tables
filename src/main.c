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

#include "../includes/config.h"
#include "../includes/helpers.h"
#include "../includes/aes.h"
#include "../includes/precalc.h"
#include "../includes/attack.h"
#include <time.h>
#include <stdlib.h> // pour srand
#include <stdio.h> // pour printf



int main(void){

    // Charge les paramètres globaux
    bool loaded = config_load("./SETTINGS.cfg");
    printf("T = %d M = %d N = %d \n", T, M, N);

    Chain table[M];

    srand((unsigned)time(NULL));

    // on gen une clé secrète (celle qu'aes va utiliser pour chiffrer) et on extend en round_keys
    key target;
    key master_key;
    get_reduced_key(master_key, 0, N);
    printf("Clé secrète:");
    print_key(master_key);

    /* Compute expanded key words */
    key round_keys[11];
    uint32_t words[44];
    size_t got = KeyExpansion(master_key, words, 44);
    if(got != 44){
        fprintf(stderr, "KeyExpansion failed (got %zu words)\n", got);
        return 1;
    }

    /* Extract round keys */
    for(int r=0;r<=10;r++) getRoundKey(words, r, round_keys[r]);

    /* calcule target = f(secret) (ici f applique AES) */
    memcpy(target, master_key, 16);
    f(target, round_keys, 10); /* target now contains f(secret) */
    printf("Target (chiffré):");
    print_key(target);    

    // ATTAQUE 
    printf("Génération des chaînes... \n");
    clock_t debut_precalc = clock();
    get_table(table, round_keys, M, N, T); // rempli la tab
    clock_t fin_precalc = clock();
    double temps_precalc = (double)(fin_precalc - debut_precalc) / CLOCKS_PER_SEC;
    printf("Pré-calcul terminé en %.2f secondes\n", temps_precalc);

    printf("Lancement de l'attaque... \n");
    clock_t debut_attaque = clock();
    int ok = attack(target, table, master_key, round_keys, M, N, T);
    clock_t fin_attaque = clock();
    double temps_attaque = (double)(fin_attaque - debut_attaque) / CLOCKS_PER_SEC;
    printf("Temps d'attaque : %.2f secondes\n", temps_attaque);

    printf("Résultat attaque : %s\n", ok ? "clé trouvée" : "échec");

    // free(table);
    return ok ? 0 : 1;
}
