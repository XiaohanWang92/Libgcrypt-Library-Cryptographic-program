/*
 * aes.c
 *  Created on: Jan 26, 2016
 *      Author: wangxiaohan
 */
#include "cryptogator.h"

int aes(char *plaintext, size_t size, int alg, const char *name){
	//initializing the library, use security memory
	if(!gcry_control(GCRYCTL_ANY_INITIALIZATION_P)){
				if(!gcry_check_version(GCRYPT_VERSION)){
				    fputs("version mismatch\n", stderr);
				    exit(2);
				}
				//based on manual, there are four procedures
				/*check this:
				 * https://gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html*/
				gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
				//16kB
				/* based on:
				 Allocate a pool of 16k secure memory.  This make the secure memory
				 available and also drops privileges where needed.  */
				gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
				gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
				gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
				//check initialization
				if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
				{
				  fputs ("libgcrypt has not been initialized\n", stderr);
				  abort ();
				}
		}
	//for algorithm scheme
	int algo = -1;
	//index to scan context
	size_t i;

	//get plain text size
	size_t txtLenght = size;
	//allocate memory
	char *out = malloc(size);

	//hd for decrypt
	//he for encrypt
	gcry_cipher_hd_t hd;
	gcry_cipher_hd_t he;

	//get algorithm macro for different AES (128 or 256)
	algo = gcry_cipher_map_name(name);
	//get key and block counter size
	size_t bsize = gcry_cipher_get_algo_blklen(alg);
	size_t ksize = gcry_cipher_get_algo_keylen(alg);

	//allocate memory for key and counter
	char *key = malloc(ksize);
	char *counter = malloc(bsize);

	//open decrypt/encrypt handler
	gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CTR, 0);
	gcry_cipher_open(&he, algo, GCRY_CIPHER_MODE_CTR, 0);

	//set key for both handler
	gcry_cipher_setkey(hd, key, ksize);
	gcry_cipher_setkey(he, key, ksize);

	//set control block
	gcry_cipher_setctr(hd, counter, bsize);
	gcry_cipher_setctr(he, counter, bsize);

//	printf("original text: \n");
//	for(i=0; i < txtLenght; i++){
//		printf("%02x", (unsigned char) plaintext[i]);
//	}
//	printf("\n\n");

	//encrypt by using handler hd (yes, I just use h(handler)d(decryption)), hehe. cipher text is in out
	gcry_cipher_encrypt(hd, out, txtLenght, plaintext, txtLenght);

//	printf("ciphered text: \n = ");
//	for(i = 0; i < txtLenght; i++){
//	    printf("%02x", (unsigned char) out[i]);
//	}
//	printf("\n\n");

	//decrypt by using handler he, decrypt in-place so the last two parameter is set to NULL, 0
	gcry_cipher_decrypt(he, out, txtLenght, NULL, 0);

//	printf("decryption text: \n");
//	//show decryption, this will be restored plain text
//	for(i = 0; i < txtLenght; i++){
//		printf("%02x", (unsigned char) out[i]);
//	}
//	printf("\n\n");
	//close handler
	gcry_cipher_close(hd);
	gcry_cipher_close(he);
	//retrun memory
	free(out);
	free(key);
	free(counter);
	return 0;
}


