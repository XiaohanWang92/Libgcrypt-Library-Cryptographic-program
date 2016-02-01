/*
 * hmac.c
 *  Created on: Jan 27, 2016
 *      Author: wangxiaohan
 */
#include "cryptogator.h"

void hmac(char *plaintext, int algo, char *scheme){
		int i;
	    int msg_len = strlen(plaintext );
	    /* Retrieve the length in bytes of the digest yielded by algorithm
	       ALGO. */
	    int hash_len = gcry_md_get_algo_dlen( algo );
	    unsigned char hash[ hash_len ];
	    char *out = (char *) malloc( sizeof(char) * ((hash_len*2)+1) );

	    /* Convenience function to calculate the hash from the data in BUFFER
	       of size LENGTH using the algorithm ALGO avoiding the creating of a
	       hash object.  The hash is returned in the caller provided buffer
	       DIGEST which must be large enough to hold the digest of the given
	       algorithm. */
	    gcry_md_hash_buffer( algo, hash, plaintext, msg_len );

	    //printf the algorithm that is used
	    //printf("%s\n", scheme);
	    //output hash key
//	    for ( i = 0; i < hash_len; i++ ) {
//	        printf ( "%02x", hash[i] );
//	    }
//	    printf( "\r\n");
	    free( out );
}
//basic is the combination of hmac and rsa 4096 function
void hmarsa(char *plaintext, int algo, char *scheme, const char *name){

	    // encrypt text length
	    int msg_len = strlen(plaintext );

	    int hash_len = gcry_md_get_algo_dlen( algo );
	    unsigned char hash[ hash_len ];
	    char *output= (char *) malloc((hash_len*2) + 1);
	    gcry_md_hash_buffer( algo, hash, plaintext, msg_len );

	    printf("For Digital Signature using SHA256 and RSA4096:\n");

	    printf("Algorithm: %s\n", scheme);

	    //output contains hex presentation of the hash key
	    int i;
	    for ( i = 0; i < hash_len; i++ ) {
	        printf ( "%02x", hash[i] );
	        sprintf(output +i*2, "%02x", hash[i]);
	    }
	    printf( "\n");
	    //generate key
	    char *public_key, *private_key;
	    gen_k4096(&public_key, &private_key);
	    //encipher
	    char *ciphertext;
	    ciphertext = encrypt(public_key, output);
	    //decipher
	    char *decrypted;
	    decrypted = decrypt(private_key, ciphertext);
	    //digital sign
	    char *signature;
	    signature = digital_sign(private_key, output);
	    printf("using SHA256 to generate signature key:\n%s\n", signature);
	    //verify
	    if (verify_sign(public_key, output, signature)) {
	    	printf("digital signature is correct, SHA256 RSA success!\n\n");
	    } else {
	    	printf("fail! re-check your code\n\n");
	    }
	    free(output);
}

