/*
 * rsa.c
 *  Created on: Jan 25, 2016
 *      Author: wangxiaohan
 */
#include "cryptogator.h"

/* library comment: Create an new S-expression object from BUFFER of size LENGTH and
   return it in RETSEXP.  With AUTODETECT set to 0 the data in BUFFER
   is expected to be in canonized format.  */
gcry_sexp_t sexp_new(const char *str) {
	gcry_error_t error;
	gcry_sexp_t sexp;
	size_t len = strlen(str);

	if ((error = gcry_sexp_new(&sexp, str, len, 1))) {
		printf("error: in sexp_new function \n");
		exit(1);
	}
	return sexp;
}

/* Copies the S-expression object SEXP into BUFFER using the format
   specified in MODE.  */
char* sexp_string(gcry_sexp_t sexp) {
	//copy s-expression into the buffer
	size_t buf_len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	char *buffer = (char*)gcry_malloc(buf_len);
	if (buffer == NULL) {
		printf("malloc fail!\n", buf_len);
		exit(1);
	}
	if (gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buffer, buf_len)==0) {
		printf("internal function gcry_sexp_sprint() wrong! bad library\n");
		exit(1);
	}
	return buffer;
}

void c_initialize(){
	if (!gcry_check_version(GCRYPT_VERSION)) {
		printf("version wrong!\n");
		exit(2);
	}
	// just disable secure memory
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}
/* library comment: Create an new S-expression object from BUFFER of size LENGTH and
   return it in RETSEXP.  With AUTODETECT set to 0 the data in BUFFER
   is expected to be in canonized format.  */
void gen_k1024(char **public_key, char **private_key) {
	gcry_error_t error;
	//build a new s-expression
	gcry_sexp_t params = sexp_new("(genkey (rsa (transient-key) (nbits 4:1024)))");
	gcry_sexp_t r_key;

	if ((error = gcry_pk_genkey(&r_key, params))) {
		printf("error in gcry_pk_genkey function \n");
		exit(1);
	}
	//build public/private key s-expressions
	/* Create and return a new S-expression from the element with index
	   NUMBER in LIST.  Note that the first element has the index 0.  If
	   there is no such element, `NULL' is returned.  */
	gcry_sexp_t public_sexp  = gcry_sexp_nth(r_key, 1);
	gcry_sexp_t private_sexp = gcry_sexp_nth(r_key, 2);
	//get keys
	*public_key = sexp_string(public_sexp);
	*private_key = sexp_string(private_sexp);
}

void gen_k4096(char **public_key, char **private_key) {
	gcry_error_t error;
	// basic the same with function gen_k1024, no more trivial comments
	gcry_sexp_t params = sexp_new("(genkey (rsa (transient-key) (nbits 4:4096)))");
	gcry_sexp_t r_key;
	if ((error = gcry_pk_genkey(&r_key, params))) {
		printf("error in gcry_pk_genkey function \n");
		exit(1);
	}

	gcry_sexp_t public_sexp  = gcry_sexp_nth(r_key, 1);
	gcry_sexp_t private_sexp = gcry_sexp_nth(r_key, 2);
	*public_key = sexp_string(public_sexp);
	*private_key = sexp_string(private_sexp);
}

char* encrypt(char *public_key, char *plaintext){
	gcry_error_t error;
	//multi-precision integer
	gcry_mpi_t r_mpi;
	//convert hex format data stream into suitable mpi to be used in RSA algo
	if ((error = gcry_mpi_scan(&r_mpi, GCRYMPI_FMT_HEX, plaintext, 0, NULL))) {
		printf("error in gcry_mpi_scan() trace: %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t data;
	size_t erroff;
	if ((error = gcry_sexp_build(&data, &erroff, "(data (flags raw) (value %m))", r_mpi))) {
		printf("error in gcry_sexp_build trace: %ld: %s\nSource: %s\n", erroff, gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}
	//encryption begins
	gcry_sexp_t public_sexp = sexp_new(public_key);
	gcry_sexp_t r_ciph;
	if ((error = gcry_pk_encrypt(&r_ciph, data, public_sexp))) {
		printf("error in gcry_pk_encrypt trace: %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}
	return sexp_string(r_ciph);
}

char* decrypt(char *private_key, char *ciphertext){
	gcry_error_t error;
	gcry_sexp_t data = sexp_new(ciphertext);
	gcry_sexp_t private_sexp = sexp_new(private_key);
	gcry_sexp_t r_plain;
	//decrypt
	if ((error = gcry_pk_decrypt(&r_plain, data, private_sexp))) {
		printf("error in gcry_pk_decrypt trace: %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}
	/* This function is used to get and convert data from a LIST. This
	   data is assumed to be an MPI stored in the format described by
	   MPIFMT and returned as a standard Libgcrypt MPI.  The caller must
	   release this returned value using `gcry_mpi_release'.  If there is
	   no data at the given index, the index represents a list or the
	   value can't be converted to an MPI, `NULL' is returned.  */
	gcry_mpi_t r_mpi = gcry_sexp_nth_mpi(r_plain, 0, GCRYMPI_FMT_USG);
	unsigned char *plaintext;
	size_t plaintext_size;
	/* Convert the big integer A int the external representation described
	   by FORMAT and store it in a newly allocated buffer which address
	   will be put into BUFFER.  NWRITTEN receives the actual lengths of the
	   external representation. */
	if ((error = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &plaintext, &plaintext_size, r_mpi))) {
		printf("error in gcry_mpi_aprint trace: %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}
	return plaintext;
}

char* digital_sign(char *private_key, char *document){
	gcry_error_t error;
	gcry_mpi_t r_mpi;
	if ((error = gcry_mpi_scan(&r_mpi, GCRYMPI_FMT_HEX, document, 0, NULL))) {
		printf("error in gcry_mpi_scan trace: %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t data;
	size_t erroff;
	if ((error = gcry_sexp_build(&data, &erroff, "(data (flags raw) (value %m))", r_mpi))) {
		printf("error in gcry_sexp_build trace: %ld: %s\nSource: %s\n", erroff, gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t private_sexp = sexp_new(private_key);
	gcry_sexp_t r_sig;
	//sign here
	if ((error = gcry_pk_sign(&r_sig, data, private_sexp))) {
		printf("error in gcry_pk_sign trace: %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}
	return sexp_string(r_sig);
}

short verify_sign(char *public_key, char *document, char *signature){
	gcry_error_t error;
	gcry_mpi_t r_mpi;
	if ((error = gcry_mpi_scan(&r_mpi, GCRYMPI_FMT_HEX, document, 0, NULL))) {
		printf("error in gcry_mpi_scan trace: %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t data;
	size_t erroff;
	if ((error = gcry_sexp_build(&data, &erroff, "(data (flags raw) (value %m))", r_mpi))) {
		printf("error in gcry_sexp_build trace %ld: %s\nSource: %s\n", erroff, gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t sig = sexp_new(signature);
	gcry_sexp_t public_sexp = sexp_new(public_key);
	short flag = 1;
	//verify here
	if ((error = gcry_pk_verify(sig, data, public_sexp))) {
		if (gcry_err_code(error) != GPG_ERR_BAD_SIGNATURE) {
			printf("error in gcry_pk_verify trace: %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
			exit(1);
		}
		flag = 0;
	}
	return flag;
}


