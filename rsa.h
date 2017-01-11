/*
 * File: rsa.h
 * Created by Hamza ESSAYEGH (Querdos)
 */

#ifndef _H_RSA_
#define _H_RSA_

#include <gmp.h>

void generate_prime(mpz_t prime, int length);
void generate_keypair(mpz_t n, mpz_t e, mpz_t d);

int i2osp(char *X, mpz_t x, int xLen);
void os2ip(mpz_t x, unsigned char * X);

int rsaes_pkcs1_encrypt(mpz_t n, mpz_t e, unsigned char * M, char *filename);
unsigned char * rsads_pkcs1_decrypt(mpz_t n, mpz_t d, int k, unsigned char *C, char *filename);

void rsaep(mpz_t cipher, mpz_t n, mpz_t e, mpz_t message);
void rsadp(mpz_t message, mpz_t n, mpz_t d, mpz_t cipher);

#endif // _H_RSA_
