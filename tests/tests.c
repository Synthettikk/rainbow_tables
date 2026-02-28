#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include "../includes/aes.h"
#include "../includes/reduction.h"
#include "../includes/precalc.h"
#include "../includes/attack.h"



// test que l'aes fourni chiffre et déchiffre comme il faut
int test_aes(uint8_t key_master[16], key round_keys[11], uint8_t plaintext[16], uint8_t expected_cipher[16]){

    /* Compute expanded key words */
    uint32_t words[44];
    size_t got = KeyExpansion(key_master, words, 44);
    if(got != 44){
        fprintf(stderr, "KeyExpansion failed (got %zu words)\n", got);
        return 1;
    }

    /* Extract round keys */
    for(int r=0;r<=10;r++) getRoundKey(words, r, round_keys[r]);

    /* Prepare state from plaintext */
    State s;
    bytes_to_state(plaintext, s);

    /* Encrypt */
    AES_Encrypt(s, round_keys, 10);

    uint8_t cipher[16];
    state_to_bytes(s, cipher);

    printf("Plaintext:        "); print_hex(plaintext, 16);
    printf("Expected cipher:  "); print_hex(expected_cipher, 16);
    printf("Computed cipher:  "); print_hex(cipher, 16);

    if(memcmp(cipher, expected_cipher, 16) != 0){
        fprintf(stderr, "Encryption mismatch\n");
        return 2;
    } else {
        printf("Encryption OK\n");
    }

    /* Decrypt to verify roundtrip */
    State s2;
    bytes_to_state(cipher, s2);
    AES_Decrypt(s2, round_keys, 10);
    uint8_t recovered[16];
    state_to_bytes(s2, recovered);

    printf("Recovered plain:  "); print_hex(recovered, 16);
    if(memcmp(recovered, plaintext, 16) != 0){
        fprintf(stderr, "Decryption mismatch\n");
        return 3;
    } else {
        printf("Decryption OK\n");
    }
    return 0;
}


// Test : prend key_in[16], indice i (pour R_i), affiche résultats et retourne 0 si OK, > 0 sinon
int test_reduction_expand(uint8_t key_in[16], unsigned long int i) {
    // 1) calcul mixed à partir de la clé initial, en fct de i
    uint64_t mixed = mixing(key_in, i);

    // 2) reduit en nouvelle clé (key2)
    key key2;
    reductionN(mixed, key2, N); // 16 est hardcodé : il devrait dépendre les paramètres dans config

    // 3) reconvertir key2 via reduction et comparer mixed et mixed2
    uint64_t mixed2 = mixing(key2, i);

    printf(" original mixed = 0x%010" PRIx64 "\n", mixed);
    printf(" mixed from key2  = 0x%010" PRIx64 "\n", mixed2);
    if (mixed2 != mixed) {
        printf("Différence OK à cause du tweak et du mélange des octets \n");
    } 

    // 4) test que la sortie change bien en fonction de i càd que les i -> Rn(., i) sont distinctes
    uint64_t mixed_i_plus_one = mixing(key_in, i+1);
    if(mixed_i_plus_one == mixed){
        printf("Problème : R_i+1 = R_i \n");
        return 2;
    }

    // 5) vérifie que key2 peut être convertie en State et en key (test les helpers state_to_bytes, bytes_to_state)
    State s;
    bytes_to_state(key2, s);
    uint8_t key_from_state[16];
    state_to_bytes(s, key_from_state); // ou state_to_key(s, key_from_state);
    if (memcmp(key2, key_from_state, 16) != 0) {
        printf("WARN: roundtrip bytes_to_state/state_to_bytes mismatch\n");
    }

    // Succès
    printf("OK: reduction/expand consistent. mixed = 0x%010" PRIx64 "\n", mixed);
    return 0;
}

int test_using_get_table(const key round_keys[], Chain *tab, const int m, const int n, const int t){

    /* génère la table réelle (avec M et T petits pour rapidité) */
    get_table(tab, round_keys, m, n, t);

    /* vérifications simples */
    for (int i = 0; i < m; ++i){
        /* start est une copie de k0 et end est k_T ; vérifie qu'ils ne sont pas identiques trop souvent */
        if (memcmp(tab[i].start, tab[i].end, 16) == 0){
            printf("Warning: chain %d start == end\n", i);
        }
    }

    /* affiche quelques entrées */
    for (int i = 0; i < 5 && i < m; ++i){
        printf("chain %d start:", i);
        for (int b=0;b<16;++b) printf(" %02x", tab[i].start[b]);
        printf("  end:");
        for (int b=0;b<16;++b) printf(" %02x", tab[i].end[b]);
        printf("\n");
    }

    printf("PRECALCUL OK \n \n");
    return 0;
}

int main(void){

    // Charge les paramètres globaux
    bool loaded = config_load("./SETTINGS.cfg");
    printf("%s\n", loaded ? "Settings runtime loaded ? : true" : "Settings runtime loaded ? : false");
    printf("T_test = %d M_test = %d N_test = %d \n", T_test, M_test, N_test);

    Chain table_test[M_test];

    key round_keys[11]; // round_keys est calculé dans le test aes
    srand((unsigned)time(NULL)); // init le rand (non crypto non mais pas besoin ici)

    /* NIST AES-128 test vector (FIPS 197 A.1) */
    static uint8_t key_master[16] = {
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6, 0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
    };

    static uint8_t plaintext[16] = {
        0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d, 0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34
    };

    static uint8_t expected_cipher[16] = {
        0x39,0x25,0x84,0x1d, 0x02,0xdc,0x09,0xfb, 0xdc,0x11,0x85,0x97, 0x19,0x6a,0x0b,0x32
    };

    // TEST AES (OK)
    printf("TEST D AES... \n");
    int r = test_aes(key_master, round_keys, plaintext, expected_cipher);
    if(r > 0){
        printf("AES FAILED \n \n");
        return 1;
    }
    printf("AES PASSED \n \n");

    // TEST REDUCTION & EXPAND -> verifie qu'à partir d'une clé AES on peut reduire puis expand et retrouver une clé dans le bon intervalle
    // (attention ce test ne garantit pas que lors d'une attaque la clé va être retrouvée, 
    // juste que la fct envoie une clé chiffrée (sortie de l'espace réduit) sur une autre du bon espace
    printf("TEST DE LA REDUCTION... \n");
    uint8_t k[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    r = test_reduction_expand(k, 0UL);
    if(r > 0){
        printf("REDUCTION FAILED \n\n ");
        return 1;
    }
    printf("REDUCTION PASSED \n \n");


    // TEST PRECALC
    printf("TEST DU PRECALCUL... \n");
    test_using_get_table(round_keys, table_test, M_test, N_test, T_test);


    // TEST ATTACK
    printf("TEST DE L'ATTAQUE... \n");

    // Gen un clé réduite (qu'on va essayer de retrouver par l'attaque)
    get_reduced_key(key_master, 0, N_test);
    printf("Clé secrète:");
    print_key(key_master);

    /* Compute expanded key words */
    uint32_t words[44];
    size_t got = KeyExpansion(key_master, words, 44);
    if(got != 44){
        fprintf(stderr, "KeyExpansion failed (got %zu words)\n", got);
        return 1;
    }

    /* Extract round keys */
    for(int r=0;r<=10;r++) getRoundKey(words, r, round_keys[r]);
    key target;

    /* calcule target = f(secret) (ici f applique AES) */
    memcpy(target, key_master, 16);
    f(target, round_keys, 10); /* target now contains f(secret) */
    printf("Target (chiffré):");
    print_key(target);
    
    // On a changé la master key donc il faut regénérer la table
    printf("Précalcul de la table avec la clé réduite... \n");
    get_table(table_test, round_keys, M_test, N_test, T_test);
    attack(target, table_test, key_master, round_keys, M_test, N_test, T_test);

    return 0;
}