#include <stdio.h>
#include <gpg-error.h>
#include <gcrypt.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#define GCRYPT_NO_DEPRECATED

//AES mode
int aes(char *plaintext, size_t size, int alg, const char *name);
//build new s-expression
gcry_sexp_t sexp_new(const char *str);
//return s-expression string
char* sexp_string(gcry_sexp_t sexp);
//initialize crypt environment when using RSA
void c_initialize();
//RSA 1024
void gen_k1024(char **public_key, char **private_key);
//RSA 4096
void gen_k4096(char **public_key, char **private_key);
//RSA encrypt
char* encrypt(char *public_key, char *plaintext);
//RSA decrypt
char* decrypt(char *private_key, char *ciphertext);
//digital sign generate (use private key)
char* digital_sign(char *private_key, char *document);
//verify digital sign (use public key)
short verify_sign(char *public_key, char *document, char *signature);
//HMAC: for MD5 SHA1 SHA256
void hmac(char *plaintext, int algo, char *description);
//HMAC256 + RSA4096
void hmarsa(char *plaintext, int algo, char *description, const char *name);
