/*
    Katie Moffitt
    CS 483
    Sept. 16, 2023

    This project is my implementation of AES using the FIPS 197 documentation
*/

#include <stdint.h>
#include <stdio.h>
#include <cmath>
#include "aes.h"

using namespace std;

// PASSED UNIT TEST
uint8_t AES::ffadd(uint8_t a, uint8_t b){
    // addition in GF(2^8) is simply an XOR
    return a ^ b;
}

// PASSED UNIT TEST
uint8_t AES::xtime(uint8_t a){
    uint8_t val = a << 1;

    if ((a >> 7) & 1){
        val = val ^ 283;
    }

    return val;
}

// PASSED UNIT TEST
uint8_t AES::ffMultiply(uint8_t a, uint8_t b){
    uint8_t val = a;
    uint8_t bVal = b;
    uint8_t sum = 0;
    uint8_t i = 0;

    while (bVal > 0){

        uint8_t temp = 1 << i;

        if (b & temp){
            sum = sum ^ val;
        }

        val = xtime(val);
        bVal = bVal >> 1;
        i++;
    }

    return sum;
}

// PASSED UNIT TEST
uint32_t AES::subWord(uint32_t word){

    uint32_t newWord = 0;

    for (int i = 0; i <= 24; i += 8){

        uint8_t y = (word >> i) & 15;
        uint8_t x = (word >> (i + 4)) & 15;

        newWord = newWord + (Sbox[x][y] << i);
    }

    return newWord;
}


// PASSED UNIT TEST
uint32_t AES::rotWord(uint32_t word){

    uint32_t newWord = 0;

    //printf("%x\n", word);

        for (int i = 0; i <= 24; i += 8){

            uint8_t byte = (word >> i) & 255;

            if (i < 24){
                newWord = newWord + (byte << (i + 8));
            }
            else {
                newWord = newWord + byte;
            }
        }

    return newWord;
}

uint32_t word(uint8_t byte1, uint8_t byte2, uint8_t byte3, uint8_t byte4){

    uint32_t word = 0;

    word = word + byte1 + (byte2 << 8) + (byte3 << 16) + (byte4 << 24);

    return word;
}

// PASSED UNIT TEST
uint32_t* AES::keyExpansion(uint8_t key[16], uint32_t w[]){

    int i = 0;
    uint32_t temp;

    // initialize key schedule 0-Nk
    while (i < Nk){
        w[i] = word(key[4*i+3], key[4*i+2], key[4*i+1], key[4*i]);
        i++;
    }

    // reset increment variable
    i = Nk;

    while (i < (Nb * (Nr + 1))){

        temp = w[i - 1];

        // rotate -> sub -> ^ Rcon[] (given by FIPS 197)
        if (i % Nk == 0){
            temp = subWord(rotWord(temp)) ^ Rcon[i/Nk];
        }
        // for keys > 4, an additional subword
        else if (Nk > 6 && (i % Nk) == 4){
            temp = subWord(temp);
        }

        w[i] = w[i - Nk] ^ temp;

        i++;
    }

    return w;
}

// PASSED UNIT TEST
uint8_t** AES::subBytes(uint8_t **state){

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){

            // break up hex into coord. like 0x(x)(y)
            uint8_t y = state[i][j] & 15;
            uint8_t x = (state[i][j] >> 4) & 15;

            state[i][j] = Sbox[x][y];
        }
    }

    return state;
}

// PASSED UNIT TEST
uint8_t** AES::shiftRows(uint8_t **state){

    uint8_t** new_state = new uint8_t*[4];
    
    for (int i = 0; i < Nb; i++){
        new_state[i] = new uint8_t[Nb];
    }

    for (int i = 0; i < 4; i++){
        for(int j = 0; j < Nb; j++){
            if (i == 0){
                new_state[i][j] = state[i][j];
            }
            else{
                // shift row to the left i places
                new_state[i][j] = state[i][(j + i) % Nb];
            }
        }
    }

    return new_state;
}

// UNIT TESTED
uint8_t** AES::mixColumns(uint8_t **state){

    uint8_t** new_state = new uint8_t*[4];
    
    for (int i = 0; i < Nb; i++){
        new_state[i] = new uint8_t[Nb];
    }

    uint8_t i = 0;


    // multiply columns by polynomials given by FIPS 197 documentation
    while (i < Nb){
        new_state[0][i] = (ffMultiply(state[0][i], 2)) ^ (ffMultiply(state[1][i], 3)) ^ (state[2][i]) ^ (state[3][i]);
        new_state[1][i] = (state[0][i]) ^ (ffMultiply( state[1][i], 2)) ^ (ffMultiply(state[2][i], 3)) ^ (state[3][i]);
        new_state[2][i] = (state[0][i]) ^ (state[1][i]) ^ (ffMultiply( state[2][i], 2)) ^ (ffMultiply(state[3][i], 3));
        new_state[3][i] = (ffMultiply(state[0][i], 3)) ^ (state[1][i]) ^ (state[2][i]) ^ (ffMultiply(state[3][i], 2));

        i++;
    }

    return new_state;
}

// PASSED UNIT TEST
uint8_t** AES::addRoundKey(uint8_t **state, uint32_t w[]){

    uint8_t** new_state = new uint8_t*[4];
    
    for (int i = 0; i < Nb; i++){
        new_state[i] = new uint8_t[Nb];
    }

    uint8_t i = 0;

    // break up words into 8 bytes and set in state array, initialize 
    // key schedule (w) with values according to current round
    while (i < Nb){
        uint32_t word = w[(round_counter * Nb) + i];

        new_state[0][i] = state[0][i] ^ ((word >> 24) & 255);
        new_state[1][i] = state[1][i] ^ ((word >> 16) & 255);
        new_state[2][i] = state[2][i] ^ ((word >> 8) & 255);
        new_state[3][i] = state[3][i] ^ (word & 255);

        i++;
    }

    return new_state;
}

void AES::cipherPrint(uint8_t **new_state, char *s){
    printf("round[%2d].%5s     ", round_counter, s);
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < Nb; j++){
                printf("%02x", new_state[j][i]);
            }
        }
    printf("\n");
}

// PASSED UNIT TEST
uint8_t* AES::cipher(uint8_t *in, uint8_t *out, uint32_t *w){

    printf("CIPHER (ENCRYPT):\n");

    round_counter = 0;
    
    uint8_t** new_state = new uint8_t*[4];
    
    for (int i = 0; i < Nb; i++){
        new_state[i] = new uint8_t[Nb];
    }

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
            new_state[j][i] = in[(i * Nb) + j];
        }
    }

    printf("round[%2d].input     ", round_counter);
    for (int i = 0; i < 16; i++){
        printf("%02x", in[i]);
    }
    printf("\n");

    printf("round[%2d].k_sch     ", round_counter);
    for (int i = 0; i < Nb; i++){
        printf("%08x", w[i]);
    }
    printf("\n");

    // first round just add key
    new_state = addRoundKey(new_state, w);

    round_counter++;

    /*
    * for each round do sub -> shift -> mix -> add
    */
    for (int i = 1; i < Nr; i++){
        cipherPrint(new_state, (char*)"start");

        new_state = subBytes(new_state);
        cipherPrint(new_state, (char*)"s_box");
        new_state = shiftRows(new_state);
        cipherPrint(new_state, (char*)"s_row");
        new_state = mixColumns(new_state);
        cipherPrint(new_state, (char*)"m_col");
        new_state = addRoundKey(new_state, w);

        printf("round[%2d].k_sch     ", round_counter);
        for (int i = 0; i < Nb; i++){
            printf("%08x", w[(round_counter * Nb) + i]);
        }
        printf("\n");

        round_counter++;
    }

    // final round follows all steps except mix
    cipherPrint(new_state, (char*)"start");
    new_state = subBytes(new_state);
    cipherPrint(new_state, (char*)"s_box");
    new_state = shiftRows(new_state);
    cipherPrint(new_state, (char*)"s_row");
    new_state = addRoundKey(new_state, w);

    printf("round[%2d].k_sch     ", round_counter);
    for (int i = 0; i < Nb; i++){
        printf("%08x", w[(round_counter * Nb) + i]);
    }
    printf("\n");

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
            out[(i * Nb) + j] = new_state[j][i];
        }
    }

    printf("round[%2d].output    ", round_counter);
    for (int i = 0; i < Nb * 4; i++){
        printf("%02x", out[i]);
    }
    printf("\n");

    k_schedule = w;

    return out;
}

uint8_t** AES::invShiftRows(uint8_t **state){

    uint8_t** new_state = new uint8_t*[4];
    
    for (int i = 0; i < Nb; i++){
        new_state[i] = new uint8_t[Nb];
    }

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
            if (i == 0){
                new_state[i][j] = state[i][j];
            }
            else{
                // shift all rows after the first to the right by j places
                new_state[i][j] = state[i][(j + (Nb - i)) % Nb];
            }
        }
    }

    return new_state;
}

uint8_t** AES::invSubBytes(uint8_t **state){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
            // split hex number into coord. like : 0x(x)(y)
            uint8_t y = state[i][j] & 15;
            uint8_t x = (state[i][j] >> 4) & 15;

            state[i][j] = InvSbox[x][y];
        }
    }

    return state;
}

uint8_t** AES::invMixColumns(uint8_t **state){
    uint8_t** new_state = new uint8_t*[4];
    
    for (int i = 0; i < Nb; i++){
        new_state[i] = new uint8_t[Nb];
    }

    uint8_t i = 0;

    // multiply columns by polynomials given by FIPS 197 documentation
    while (i < Nb){
        new_state[0][i] = (ffMultiply(state[0][i], 0x0e)) ^ (ffMultiply(state[1][i], 0x0b)) ^ (ffMultiply(state[2][i], 0x0d)) ^ (ffMultiply(state[3][i], 0x09));
        new_state[1][i] = (ffMultiply(state[0][i], 0x09)) ^ (ffMultiply( state[1][i], 0x0e)) ^ (ffMultiply(state[2][i], 0x0b)) ^ (ffMultiply(state[3][i], 0x0d));
        new_state[2][i] = (ffMultiply(state[0][i], 0x0d)) ^ (ffMultiply(state[1][i], 0x09)) ^ (ffMultiply( state[2][i], 0x0e)) ^ (ffMultiply(state[3][i], 0x0b));
        new_state[3][i] = (ffMultiply(state[0][i], 0x0b)) ^ (ffMultiply(state[1][i], 0x0d)) ^ (ffMultiply(state[2][i], 0x09)) ^ (ffMultiply(state[3][i], 0x0e));

        i++;
    }

    return new_state;
}

void AES::invCipherPrint(uint8_t **new_state, char *s){
    printf("round[%2d].%6s    ", Nr - round_counter, s);
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < Nb; j++){
                printf("%02x", new_state[j][i]);
            }
        }
    printf("\n");
}

uint8_t* AES::invCipher(uint8_t *in, uint8_t *out){
    
    printf("\nINVERSE CIPHER (DECRYPT):\n");
    
    uint8_t** new_state = new uint8_t*[4];
    
    for (int i = 0; i < Nb; i++){
        new_state[i] = new uint8_t[Nb];
    }

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
            new_state[j][i] = in[(i * Nb) + j];
        }
    }

    printf("round[%2d].iinput    ", Nr - round_counter);
    for (int i = 0; i < 16; i++){
        printf("%02x", in[i]);
    }
    printf("\n");

    printf("round[%2d].ik_sch    ", Nr - round_counter);
    for (int i = 0; i < Nb; i++){
        printf("%08x", k_schedule[(round_counter * Nb) + i]);
    }
    printf("\n");

    new_state = addRoundKey(new_state, k_schedule);

    round_counter--;

    /*
    *   for each round, shift -> sub -> add -> mix
    */
    for (int i = 1; i < Nr; i++){
        invCipherPrint(new_state, (char*)"istart");

        new_state = invShiftRows(new_state);
        invCipherPrint(new_state, (char*)"is_row");
        new_state = invSubBytes(new_state);
        invCipherPrint(new_state, (char*)"is_box");

        printf("round[%2d].ik_sch    ", Nr - round_counter);
        for (int i = 0; i < Nb; i++){
            printf("%08x", k_schedule[(round_counter * Nb) + i]);
        }
        printf("\n");

        new_state = addRoundKey(new_state, k_schedule);
        invCipherPrint(new_state, (char*)"ik_add");

        new_state = invMixColumns(new_state);

        round_counter--;
    }

    // final round repeat all steps except mix (for memory)
    invCipherPrint(new_state, (char*)"istart");
    new_state = invShiftRows(new_state);
    invCipherPrint(new_state, (char*)"is_row");
    new_state = invSubBytes(new_state);
    invCipherPrint(new_state, (char*)"is_box");
    new_state = addRoundKey(new_state, k_schedule);

    printf("round[%2d].ik_sch    ", Nr - round_counter);
    for (int i = 0; i < Nb; i++){
        printf("%08x", k_schedule[i]);
    }
    printf("\n");

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
            out[(i * Nb) + j] = new_state[j][i];
        }
    }

    printf("round[%2d].ioutput   ", Nr - round_counter);
    for (int i = 0; i < Nb * 4; i++){
        printf("%02x", out[i]);
    }
    printf("\n");

    return out;
}
