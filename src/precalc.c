
/*
    On veut une table de M chaînes, chacune de longueur T.
    Chaque chaîne commence par une clé random k_0, puis on calcul k_1 = R_i(AES_Encrypt(k_0))), etc jusqu'à k_T et on stocke 
    (k_0, k_T) M fois pour les différents k_0.

    On appelle R la fonction de réduction
*/

#include <stdio.h>
#include "../includes/precalc.h"
#include "../includes/aes.h"
#include "../includes/config.h"
#include "../includes/reduction.h"



// tableau de M chaînes, chaque chaîne étant une séquence de T clés reliées par des fonctions f et R : k_1 = R(f(k_0)), où f = AES_Encrypt ici.
void get_table(Chain *tab, const key round_keys[], const int m, const int n, const int t){ // on donne les roundkeys car on a besoin d'executer l'aes avec la clé maitre mais en vrai on les connait pas
    
    // init le random (deja fait dans le main)
    // srand(time(NULL));

    for(int i = 0; i < m; i++){

        // génère un k_0
        key key0;
        get_reduced_key(key0, 0, n);

        // stocke k_0 dans la tab (fait une copie indép)
        memcpy(tab[i].start, key0, 16);

        // construction de la chaine : k0 -> k1 = R(f(k0)) -> ...
        for(int j = 0; j < t; j++){
            f(key0, round_keys, 10);
            R(key0, j, n);
        }

        // stocke kT dans la tab :
        memcpy(tab[i].end, key0, 16);

        // Affiche la progression tous les 100 chaînes
        if (i % 100 == 0) printf("Chaîne %d générée\n", i);
    }
}

