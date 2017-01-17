/*
 * File: main.c
 * Created by Hamza ESSAYEGH (Querdos)
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <gmp.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "rsa.h"
#include "rsa_keys.h"

#define BASE_SAVE 		61
#define MAX_CHARS_LINES 50

/**
 * Encrypt a given file with a pre-saved public key
 */
void encrypt_file(char *filename_plain) {
	// vars
	FILE *fp_plain, *size_of_file, *fp_rsa;
	mpz_t n, e;
	unsigned char **encrypted, **plain;
	unsigned long size, max_line;
	char command_wc[11], count[3], ch_plain;
	int k, i, j, nb_elements, step, status_pubkey;
	
	// generating the key pair
	status_pubkey = load_pub(n, e);
	if (status_pubkey == -1) {
		exit(1);
	}
	k = mpz_size(n) * GMP_LIMB_BITS / 8;
	
	// opening the file (not encrypted)
	fp_plain = fopen(filename_plain, "r");
	
	// exception
	if (NULL == fp_plain) {
		printf("Unable to open the file '%s'\n", filename_plain);
		mpz_clears(n, e, NULL);
		exit(1);
	}

	// retreiving size of *plain
	sprintf(command_wc, "wc -c < %s", filename_plain);
	size_of_file = popen(command_wc, "r");
	
	fgets(count, 10, size_of_file);
	pclose(size_of_file);
	size = atoi(count);
	
	// message length can be a maximum of (k-11)
	// allocating memory for plain
	nb_elements = 0;
	plain = malloc((((size-size%(k-11))/(k-11)) + 1) * sizeof(*plain));
	if (NULL == plain) {
		printf("Memory error.\n");
		mpz_clears(n, e, NULL);
		exit(1);
	}
	
	for (i=0; i<((size-size%(k-11))/(k-11)); i++) {
		plain[i] = malloc((k-11) * sizeof(plain[i]));
		if (NULL == plain[i]) {
			printf("Memory error\n");
			mpz_clears(n, e, NULL);
			exit(1);
		}
		
		memset(plain[i], '\0', (k-11));
		nb_elements++;
	}
	
	plain[i] = malloc((size % (k-11)) * sizeof(plain[i]));
	if (NULL == plain[i]) {
		printf("Memory error\n");
		mpz_clears(n, e, NULL);
		exit(1);
	}
	memset(plain[i], '\0', size % (k-11));
	nb_elements++;
	
	// retrieving plain text
	i = -1;
	step = 0;
	while (1) {
		i++;
		if (step != (nb_elements - 1)) {
			if (i < (k-11)) {
				plain[step][i] = fgetc(fp_plain);
			} else {
				i = -1;
				step++;
				continue;
			}
		} else {
			ch_plain = fgetc(fp_plain);
			if (feof(fp_plain)) {
				fclose(fp_plain);
				break;
			} else {
				plain[step][i] = ch_plain;
			}
		}
	}
	
	// encrypting
	encrypted = malloc((((size-size%(k-11))/(k-11)) + 1) * sizeof(*encrypted));
	if (NULL == encrypted) {
		printf("Memory error");
		mpz_clears(n, e, NULL);
		exit(1);
	}
	
	fp_rsa = fopen("encrypted", "w");
	for (i=0; i<nb_elements; i++) {
		encrypted[i] = malloc(k * sizeof(encrypted[i]));
		if (NULL == encrypted[i]) {
			printf("Memory error.\n");
			mpz_clears(n, e, NULL);
			exit(1);
		}
		memset(encrypted[i], '\0', k);
		
		encrypted[i] = rsaes_pkcs1_encrypt(n, e, plain[i]);
		free(plain[i]);
		if (NULL == encrypted[i]) {
			free(plain);
			free(encrypted);
			mpz_clears(n, e, NULL);
			exit(1);
		}
		
		// write
		for (j=0; j<k; j++) {
			fputc(encrypted[i][j], fp_rsa);
		}
		
		free(encrypted[i]);
	}
	fclose(fp_rsa);
	
	// clearing pub key
	mpz_clears(n, e, NULL);
	free(plain);
	free(encrypted);
}

/**
 * Decrypt a given file with a pre-saved private key
 */
void decrypt_file(char *filename_encrypted) {
	// vars
	FILE *chars_count, *fp_encrypted, *fp_rsa;
	unsigned char **encrypted, **decrypted;
	char *wc_command, chars_result[5];
	mpz_t n, d;
	int chars, i, j, k, nb_decrypt;
	
	// retrieving rsa key pair (private)
	if (load_priv(n, d) == -1) {
		mpz_clears(n, d, NULL);
		exit(1);
	}
	k = mpz_size(n) * GMP_LIMB_BITS / 8;
	
	// trying to open the file
	fp_encrypted = fopen(filename_encrypted, "r");
	if (NULL == fp_encrypted) {
		printf("File doesn't exists. Aborting.\n");
		exit(1);
	}
	
	// number of chars in encrypted file
	wc_command = malloc((strlen(filename_encrypted) + 8) * sizeof(char *));
	sprintf(wc_command, "wc -c < %s", filename_encrypted);
	
	chars_count = popen(wc_command, "r");
	free(wc_command);
	fgets(chars_result, 5, chars_count);
	pclose(chars_count);
	chars = atoi(chars_result);
	
	fp_rsa = fopen("decrypted", "w");
	if (NULL == fp_rsa) {
		printf("Unable to open a file for decryption. Aborting.\n");
		exit(1);
	}
	
	if (chars > k) {
		// how many times we will decrypt
		nb_decrypt = chars / k;
		
		// allocating
		encrypted = malloc(nb_decrypt * sizeof(*encrypted));
		decrypted = malloc(nb_decrypt * sizeof(*decrypted));
		if (NULL == encrypted) {
			printf("Memory error.\n");
			exit(1);
		}
		
		for (i=0; i<nb_decrypt; i++) {
			// allocating
			encrypted[i] = malloc(k * sizeof(encrypted[i]));
			if (NULL == encrypted[i]) {
				printf("Memory error.\n");
				exit(1);
			}
			
			// retrieving first part
			for (j=0; j<k; j++) {				
				encrypted[i][j] = fgetc(fp_encrypted);
			}
			
			decrypted[i] = rsads_pkcs1_decrypt(n, d, k, encrypted[i]);
			free(encrypted[i]);
			if (NULL == decrypted[i]) {
				exit(1);
			}
			
			for (j=0; j<strlen(decrypted[i]); j++) {
				fputc(decrypted[i][j], fp_rsa);
			}
			free(decrypted[i]);
		}
	} else {
		// allocating
		encrypted = malloc(sizeof(*encrypted));
		encrypted[0] = malloc(k * sizeof(encrypted[0]));	
		
		// TODO
		
		free(encrypted[0]);
		free(encrypted);
	}
	
	fclose(fp_encrypted);
	fclose(fp_rsa);
	
}

/**
 * Save a key pair (public and private key) into .rsa directory 
 */
void key_pair() {
	int dir_exists;
	mpz_t n, e, d;
	
	// checking .rsa existance
	dir_exists = mkdir(".rsa", 0755);
	
	// .rsa exists
	if (-1 == dir_exists) {
		char user_choice;
		printf("Directory exists. Generate new key pair? [y|n] ");
		user_choice = getchar();
		
		if (user_choice != 'y' && user_choice != 'n') {
			printf("Aborting.\n");
			exit(1);
		}
		
		if ('y' == user_choice) {
			// init
			mpz_inits(n, e, d, NULL);
			
			// generating key pair
			printf("Generating key pair...");
			generate_keypair(n, e, d);
			printf(" Done.\n");
			
			// saving
			if (-1 == save_keypair(n, e, d)) {
				mpz_clears(n, e, d, NULL);
				exit(1);
			}
			
			// cleaning
			mpz_clears(n, e, d, NULL);
		}
	}
	
	// .rsa doesn't exists
	else {
		// inits
		mpz_inits(n, e, d, NULL);
		
		// generating
		printf("Generating key pair...");
		generate_keypair(n, e, d);
		printf(" Done.\n");
		
		// saving
		save_keypair(n, e, d);
		
		// cleaning
		mpz_clears(n, e, d, NULL);
	}
}

int main(int argc, char** argv) {
	// init time
	srand(time(NULL));
	
	// checking number of arguments
	if (argc > 3 || argc == 1) {
		printf("Usage: %s --[decrypt, encrypt, generate-key-pair] file\nUsage: %s --generate-key-pair\n\n", argv[0], argv[0]);
		return EXIT_FAILURE;
	}
	
	// for encryption
	if (strcmp(argv[1], "--encrypt") == 0) {		
		encrypt_file(argv[2]);
	}
	
	// for decryption
	else if (strcmp(argv[1], "--decrypt") == 0) {
		decrypt_file(argv[2]);
	}
	
	// key pair generation
	else if (strcmp(argv[1], "--generate-key-pair") == 0) {
		key_pair();
	}
	
	// option not recognized
	else {
		printf("Usage: %s --[decrypt, encrypt, generate-key-pair] file\n", argv[0]);
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}
