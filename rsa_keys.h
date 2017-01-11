/*
 * File: rsa_keys.c
 * Created by Hamza ESSAYEGH (Querdos)
 */

#ifndef _H_RSA_KEYS_
#define _H_RSA_KEYS_

int save_keypair(mpz_t n, mpz_t e, mpz_t d);

int load_pub(mpz_t n, mpz_t e);
int load_priv(mpz_t n, mpz_t d);

#endif
