# Attaque par tables arc-en-ciel (rainbow tables)

Le but de ce projet est d'implémenter en langage C une attaque par chaînes arc-en-ciel sur AES 128.

En 3 temps :

1. Comprendre les aspects mathématiques des rainbow tables
2. Implémenter l'attaque sur des paramètres réalistes pour ordinateurs personnels
3. Refactoring du code pour structurer le projet.

Rappelons le principe de l'attaque :

## CONTEXTE

On suppose que l'on a une clé secrète d'un AES 128 à retrouver et on suppose que l'on sait que cette clé est dans un espace réduit de taille 40bits -> k in [0, 2^40].
On choisit m plaintexts (blocs de 128b) connus, concrètement on en prendra qu'un (devrait suffire).

## PRINCIPE

Faire une recherche exhaustive coûte trop cher : 2^40, le but des rainbow tables est de transferer ce temps de calcul trop long en un précalcul càd un coût mémoire pour que l'attaque soit beaucoup plus rapide.
L'idée est de partir d'un plaintext et d'une clé random k0 (la clé peut aussi être l'antécédent d'une fonction de hashage),
de le chiffrer (ou hasher), et de réduire ce chiffré pour qu'il appartienne à l'espace des clés :
ce qui donne une nouvelle clé k1, puis de recommencer T fois. On obtient alors une chaine de longueur T contenant T clés k_i possibles : k0 -> k1 ... -> kT.
On stocke (k0, kT).
Le but est de couvrir un maximum de clés, afin d'avoir la meilleure proba possible de retrouver la clé.

## PRECALCUL

Pour chaque plain (on peut en prendre qu'un) on choisit plusieurs k0 (un par chaine) et on produit M chaines de longueur T :
k0 -> k1 -> ... -> kT
En pratique on veut que M x T > N = 2^40 pour couvrir l'ensemble des clés possibles (on prend > au cas où on tomberait sur des collions, càd pls fois la même clé dans les chaines)
On stocke M couples (k_0, k_T) -> c'est notre 'rainbow table'.

## ATTAQUE

On part soit d'un plaintext P que l'on chiffre pour obtenir un ciphertext C, soit d'un hashé y.
On a notre table contenant les couples (x0, xT) venant des chaines x0 -> H(x0) -> R0(H(x0)) = x1 -> H(x1) -> R1(H(x1)) = x2 -> ... -> x_t.
L'idée est que y peut être (ou est si la table est suffisemment fournie) le résultat intermédiaire d'une des chaînes.
On reconstruit alors les y_k = y_k = R_k(H(...(R_{t-1}(H(y))...))) pour k entre T-1 et 0 afin de parcourir l'ensemble des 'positions' possibles de la chaine,
c'est-à-dire l'ensemble des résultats intermédiaires possibles venant de y dans les chaînes.
Pour chaque k on regarde si la valeur y_kcorrespond à un x_T dans la table.
Si oui, on reconstitue la chaîne à partir de x_0 jusqu'à tomber sur le x_j tel que H(x_j) = y.
On a alors retrouvé  un antécédent de y par H -> x_j. Notons que pour une fonction de hashage (non bijective), x_j peut ne pas être la clé recherchée (seconde préimage) même si elle donne le même hashé (ce qui ne pose pas de problème) puisque l'on a un antécédant qui marche aussi. Par contre, ceci n'est pas le cas pour AES qui est une permutation (bijectif) pour une clé donnée.

## COMPROMIS TEMPS MEMOIRE

La brut force revient à avoir une chaine de longueur T = 2^40,
on test toutes les clés les unes après les autres pour voir laquelle donne le chiffré attendu.
Si par contre T = 1, alors pour couvrir toutes les clés cela revient à construire une table qui stocke les 2^40 clés (énorme en mémoire),
la recherche devient alors très rapide : pour un chiffré donné on applique la réduction pour le ramener dans l'espace des clés,
on cherche alors kT dans la table et on renvoie la k0 correspondante (k0 la bonne clé) -> cest du O(1).
Donc la longueur T des chaines donne le temps (coût) de calcul, tandis que le nombre M de chaines donne le coût mémoire.
Rappel : on veut N < M x T de sorte que toutes les clés aient été parcourues par les chaînes.
Concrètement si on veut un équilibre on peut prendre M ~ T ~ N^{1/2}, et on peut jouer sur les paramètres M et T pour diminuer soit le temps de
calcul (en augmentant M et diminuant T, en conservant N < M x T) ou vice versa.

## Détails mathématiques et choix d'implémentation

Voir le pdf "Rainbow_tables.pdf".
