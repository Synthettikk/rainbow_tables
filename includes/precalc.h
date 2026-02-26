#ifndef precalc_h
#define precalc_h


#include "config.h"


// tableau de M chaînes, chaque chaîne étant une séquence de T clés reliées par des fonctions f et R : k_1 = R(f(k_0)), où f = AES_Encrypt ici.
void get_table(Chain *tab, const key round_keys[], const int m, const int n, const int t); // on donne les roundkeys car on a besoin d'executer l'aes avec la clé maitre mais en vrai on les connait pas

#endif // precalc_h