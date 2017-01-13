/*
 * File: rsa.c
 * Created by Hamza ESSAYEGH (Querdos)
 */
 
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <gmp.h>
#include <string.h>

#define MOD_LENGTH 	1024
#define MIN 		5000
#define MAX 		50000

/**
 * Generate a prime with a bit length of 'length'
 */
void generate_prime(mpz_t prime, int length) {
	// vars
	gmp_randstate_t rs;
	
	// Initializing rs
	gmp_randinit_default(rs);
	
	// Seeding the random state
	gmp_randseed_ui(rs, (rand() % MAX) + MIN);
	
	// Randomization
	mpz_urandomb(prime, rs, length);
	
	// Check if prime
	while (mpz_probab_prime_p(prime, 5) == 0) {
		mpz_nextprime(prime, prime);
	}
}

/**
 * Generate a key pair (n, e) and (n, d)
 * The return value: [n, e, d]
 */
void generate_keypair(mpz_t n, mpz_t e, mpz_t d) {
	// Vars
	mpz_t p, q;
	mpz_t p1, q1;
	mpz_t lambda; // totient, according to PKCS#1
	
	// Assigning
	// With p and q of 512bits, the modulus will be 1024bits
	mpz_inits(p, q, NULL);
	generate_prime(p, MOD_LENGTH/2); 
	generate_prime(q, MOD_LENGTH/2);
	
	mpz_inits(p1, q1, n, NULL);
	mpz_mul(n, p, q); 		// n = p * q
	mpz_sub_ui(p1, p, 1); 	// p1 = p-1
	mpz_sub_ui(q1, q, 1); 	// q1 = q-1
	mpz_clears(p, q, NULL);
	
	// totient
	mpz_init(lambda);
	mpz_lcm(lambda, p1, q1); // lambda = lcm(p-1, q-1);
	mpz_clears(p1, q1, NULL);
	
	// popular choice for the public exponents is e = 65537
	mpz_set_ui(e, 65537);
	
	// d = e^(-1) mod lambda
	mpz_invert(d, e, lambda);
	
	// Clearing
	mpz_clear(lambda);
}

/**
 * I2OSP converts a nonnegative integer to an octet string of a
 * specified length.
 * 
 * Input:
 *  x        nonnegative integer to be converted
 *  xLen     intended length of the resulting octet string
 *
 * Output:
 *  X        corresponding octet string of length xLen
 *
 * Error: "integer too large"
 */
int i2osp(char *X, mpz_t x, int xLen) {
	// vars
	mpz_t pow256, q, r, x_copy;
	unsigned char temp;
	int i;
	
	// init
	mpz_init(pow256);
	mpz_ui_pow_ui(pow256, 256, xLen);
	
	// length checking
	if (mpz_cmp(x, pow256) >= 0) {
		printf("Integer too large\n");
		mpz_clear(pow256);
		return -1;
	}
	
	// clearing pow256
	mpz_clear(pow256);
		
	// setting initial values
	mpz_init(x_copy);
	mpz_set(x_copy, x);

	X = malloc(xLen * sizeof(unsigned char *));
	memset(X, '\0', sizeof(X));
	
	i = xLen - 1;
	mpz_inits(q, r, NULL);
	while (mpz_cmp_d(x_copy, 256) > 0) {
		 mpz_tdiv_q_ui(q, x_copy, 256);
		 mpz_tdiv_r_ui(r, x_copy, 256);
		 
		 X[i] = (unsigned char) mpz_get_ui(r);
		 i--;
		 
		 mpz_set(x_copy, q);
	}
	mpz_clears(r, x_copy, NULL);
	
	// appending the rest
	X[i] = (unsigned char) mpz_get_d(q);
	
	mpz_clear(q);
	return 0;
} 

/**
 * OS2IP converts an octet string to a nonnegative integer.
 * 
 * Input:
 *  X        octet string to be converted
 *
 *  Output:
 *  x        corresponding nonnegative integer 
 */
void os2ip(mpz_t x, unsigned char *X, size_t xLen) {
	// vars
	int i;
	mpz_t x_i, pow256;
	
	// checking x (must be 0)
	mpz_set_ui(x, 0);
	
	// assigning
	mpz_inits(x_i, pow256, NULL);
	
	// summing
	for (i=xLen; i>0; i--) {	
		// 256 ^ i
		mpz_ui_pow_ui(pow256, 256, xLen-i); 
		
		// x_i * 256^i
		mpz_mul_ui(x_i, pow256, (unsigned char) X[i-1]);
		
		// adding to the result
		mpz_add(x, x, x_i);
	}
	
	// clearing
	mpz_clears(x_i, pow256, NULL);
}

/**
 * Input:
 *  (n, e)   RSA public key
 *  m        message representative, an integer between 0 and n - 1
 *
 * Output:
 *  c        ciphertext representative, an integer between 0 and n - 1
 *
 *  Error: "message representative out of range"
 *
 * Assumption: RSA public key (n, e) is valid
 */
int rsaep(mpz_t cipher, mpz_t n, mpz_t e, mpz_t message) {
	// If the message representative m is not between 0 and n - 1, output
    // "message representative out of range" and stop.
    mpz_t sub;
    int comp1, comp2;
    
    // Initialization
    mpz_init(sub);
    
    // Setting values
    mpz_sub_ui(sub, n, 1);
    comp1 = mpz_cmp_d(message, 0); // must be postive
    comp2 = mpz_cmp(message, sub); // must be negative
    
    // Checking message length
    if (comp1 < 0 || comp2 > 0) {
		printf("Message representative out of range\n");
		mpz_clear(sub);
		return -1;
	}
	
	// Clearing sub
	mpz_clear(sub);
	
	// Let c = m^e mod n
	mpz_powm(cipher, message, e, n);
	
	return 0;
}

/**
 * Input:
 *  K        RSA private key, where K has one of the following forms:
 *               - a pair (n, d)
 *               - a quintuple (p, q, dP, dQ, qInv) and a possibly empty
 *                 sequence of triplets (r_i, d_i, t_i), i = 3, ..., u
 *  c        ciphertext representative, an integer between 0 and n - 1
 *
 * Output:
 *  m        message representative, an integer between 0 and n - 1
 *
 * Error: "ciphertext representative out of range"
 *
 * Assumption: RSA private key K is valid
 */
int rsadp(mpz_t deciphered, mpz_t n, mpz_t d, mpz_t cipher) {
	mpz_t sub;
	int comp1, comp2;
	
	// initialization
	mpz_init(sub);
	
	// setting values
	mpz_sub_ui(sub, n, 1);
	comp1 = mpz_cmp_ui(cipher, 0);
	comp2 = mpz_cmp(cipher, sub);
	
	// Checking cipher representative
	if (comp1 < 0 || comp2 > 0) {
		printf("Cipher representative out of range\n");
		mpz_clear(sub);
		return -1;
	}
	
	// Let m = c^d mod n
	mpz_powm(deciphered, cipher, d, n);
	
	return 0;
}

/**
 * Input:
 *  (n, e)   recipient's RSA public key (k denotes the length in octets
 *           of the modulus n)
 *  M        message to be encrypted, an octet string of length mLen,
 *           where mLen <= k - 11
 *
 * Output:
 *  C        ciphertext, an octet string of length k
 *
 * Error: "message too long"
 */
int rsaes_pkcs1_encrypt(mpz_t n, mpz_t e, unsigned char *M, char *filename) {
	// vars
	int mLen, k;
	unsigned char *PS, *EM, *C;
	gmp_randstate_t rs;
	mpz_t m, c;
	FILE *fp_encrypted;
	int i, step, count;
	
	// assigning	
	mLen = strlen(M);
	k 	 = mpz_size(n) * GMP_LIMB_BITS / 8;
	
	// length checking 
	if (mLen > (k-11)) {
		printf("Message too large\n");
		return -1;
	}
	
	// allocating PS
	PS = malloc((k - mLen - 3) * sizeof(unsigned char *));
	memset(PS, '\0', k-mLen-3);
	
	// Generate an octet string PS of length k - mLen - 3 consisting
    // of pseudo-randomly generated nonzero octets.  The length of PS
    // will be at least eight octets.
    count = 0;
	for (i=0; i<(k-mLen-3); i++) {
		PS[i] = rand() % 255 + 1;
	}

	EM = malloc(k * sizeof(unsigned char *));
	memset(EM, '\0', k);
    
    // Concatenate PS, the message M, and other padding to form an
    // encoded message EM of length k octets as
	// EM = 00 | 02 | PS | 00 | M
	
	// setting first octets
	EM[0] = 0x00;
	EM[1] = 0x02;
	
	// concatenating PS
	i=2;
	count = 0;
	for (i; i<(k-mLen-1); i++) {
		EM[i] = PS[count];
		count++;
	}
	
	// setting 00 octets before M
	EM[i] = 0x00;
	
	// concatenating M
	i++;
	count = 0;
	for (i; i<k; i++) {
		EM[i] = M[count];
		count++;
	}
	free(PS);
	
	// Convert the encoded message EM to an integer message
    // representative m
    mpz_init(m);
    os2ip(m, EM, k);
    free(EM);
    
    // Apply the RSAEP encryption primitive to the RSA
    // public key (n, e) and the message representative m to produce
    // an integer ciphertext representative c
    mpz_init(c);
    if (-1 == rsaep(c, n, e, m)) {
		mpz_clear(c);
		mpz_clear(m);
		return -1;
	}
	
	// clearing
    mpz_clear(m);
    
    // Convert the ciphertext representative c to a ciphertext C of
    // length k octets
    if (-1 == i2osp(C, c, k)) {
		mpz_clear(c);
		free(C);
		return -1;
	}
	
	// clearing
    mpz_clear(c);
	
    // saving to file
    fp_encrypted = fopen(filename, "w");
    if (NULL == fp_encrypted) {
		printf("Unable to open file %s for saving. Aborting.\n", filename);
		free(C);
		return -1;
	}
	
    for (i=0; i<k; i++) {
		fputc(C[i], fp_encrypted);
	}
	fclose(fp_encrypted);
	
	return 0;
}

/**
 * RSAES-PKCS1-V1_5-DECRYPT (K, C)
 * 
 * Input:
 *  K        recipient's RSA private key
 *  C        ciphertext to be decrypted, an octet string of length k,
 *           where k is the length in octets of the RSA modulus n
 *
 * Output:
 *  M        message, an octet string of length at most k - 11
 *
 * Error: "decryption error"
 */
unsigned char * rsads_pkcs1_decrypt(mpz_t n, mpz_t d, int k, unsigned char *C, char* filename) {
	// vars
	int n_len, i;
	mpz_t c, m;
	unsigned char *EM;
	
	// retrieving modulus length
	n_len = strlen(mpz_get_str(NULL, 10, n));
	
	// Length checking: If the length of the ciphertext C is not k octets
    // (or if k < 11), output "decryption error" and stop.
    if (k < 11 || n_len != k) {
		printf("Decryption error.\n");
		exit(1);
	}
	
	// Convert the ciphertext C to an integer ciphertext
    // representative c
    mpz_init(c);
    //os2ip(c, C);
    
    // Apply the RSADP decryption primitive to the RSA
    // private key (n, d) and the ciphertext representative c to
    // produce an integer message representative m
	mpz_init(m);
	rsadp(m, n, d, c);
	
	// Convert the message representative m to an encoded message EM
    // of length k octets
    i2osp(EM, m, k);
    
	
	unsigned char *M;
	// TODO: Finish the function
	
	return M;
}
