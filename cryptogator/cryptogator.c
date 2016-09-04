/*libgcrypt performance benchmark
 * a sample code for libgcrypt starter
 *
 * develop environment: eclipse
 * Ubuntu 14.04 in Virtual Box, Win 8.1 OS
 *
 * copy right: Xiaohan Wang
 * Gator CSer
 * CISE Department, UFL
 * */
#include "cryptogator.h"
#include <time.h>

//comparator is used for quick sort, we sort array then find median
//there is a classic O(n) algo to find rank, but that is not our purpose
//using C build-in quicksort is enough, running time n*O(lgn)
int comparator (const void * first, const void * second)
{
    double a = *((double*)first);
    double b = *((double*)second);

    if (a > b)
    	return  1;
    if (a < b)
    	return -1;
    return 0;
}

int main(int argc, char **argv){
	//set a 7x100 2-D long type array to record elapsed time.
	/*read in file
	 *use general fread function in C library
	 *need store data length for further use
	 **/
	if(argc != 2){
	         printf("input is not good!");
		 exit(1);
	}
    	char *filename = argv[1];
	FILE * pFile;
	int lSize;
	char * buffer;
	size_t result;
	//open file
	pFile = fopen (filename, "rb" );
	if (pFile==NULL)
	{
		 fputs ("File error, can't open",stderr);
		 exit (1);
	}
	//find file ending
	fseek (pFile , 0 , SEEK_END);
	//get file size
	lSize = ftell (pFile);
	//set pointer to file starting
	rewind (pFile);
	//read in preparation
	buffer = (char*) malloc (sizeof(char)*lSize);
	if (buffer == NULL)
	{
		  fputs ("Memory error, can't allocate",stderr);
		  exit (1);
	}
	//read in
	result = fread (buffer,1, lSize, pFile);
	if (result != lSize)
	{
		  fputs ("Reading error, can't read massage",stderr);
		  exit (1);
	}

	char * plain_text;
	plain_text = buffer;
	size_t size = sizeof(char)*lSize;

	struct timespec start_time, end_time;
	double time_elapse[101] = {0};
	int round=0;

	//AES128, ctr
	printf("AES128 mode 100 times check\n");
	int alg = GCRY_CIPHER_AES;
	char *name = "aes128";

	for( ; round<101; round++){
		clock_gettime(0x01, &start_time);
		aes(plain_text, size, alg, name);
		clock_gettime(0x01, &end_time);
		time_elapse[round]=end_time.tv_sec*1000000000.0+end_time.tv_nsec;
		time_elapse[round]=time_elapse[round]-start_time.tv_sec*1000000000.0-start_time.tv_nsec;
		time_elapse[round] /= 1000.0;
		if(round!=0)
			printf("round %d : %.4lf microsec\n", round, time_elapse[round]);
	}

	qsort (time_elapse, sizeof(time_elapse)/sizeof(*time_elapse), sizeof(*time_elapse), comparator);

	double sum=0;
	for(round=1; round<101; round++){
		sum += time_elapse[round];
	}
	printf("/********************/\n");
	printf("result:\nmedian is : %.4lf microsec and average is :  %.4lf microsec\n", time_elapse[50], sum/100);
	printf("/********************/\n");
	double aes128median = time_elapse[50];
	double aes128avg = sum/100;


	//AES256, ctr
	printf("\n\nAES256 mode 100 times check\n");
	alg = GCRY_CIPHER_AES256;
	name = "aes256";

	//notice: we need to convert time into microsecond
	//we need combine decimal digits and digits after decimal point first
	//then we need calculate time difference
	//finally we need to convert it to microsecond

//for aes skip the first round,
//because first round involves initialization and resource allocation, the time is not accurate
	for(round=0 ; round<101; round++){
		clock_gettime(0x01, &start_time);
		aes(plain_text, size, alg, name);
		clock_gettime(0x01, &end_time);
		time_elapse[round]=end_time.tv_sec*1000000000.0+end_time.tv_nsec;
		time_elapse[round]=time_elapse[round]-start_time.tv_sec*1000000000.0-start_time.tv_nsec;
		time_elapse[round] /= 1000.0;
		if(round!=0)
			printf("round %d : %.4lf microsec\n", round, time_elapse[round]);
	}
	qsort (time_elapse, sizeof(time_elapse)/sizeof(*time_elapse), sizeof(*time_elapse), comparator);

	sum=0;
	for(round=1; round<101; round++){
		sum += time_elapse[round];
	}
	printf("/********************/\n");
	printf("result:\nmedian is : %.4lf microsec and average is :  %.4lf microsec\n", time_elapse[50], sum/100);
	printf("/********************/\n");
	double aes256median = time_elapse[50];
	double aes256avg = sum/100;

	/*
	 * transform plain text
	 * into hex numeric pair
	 *for RSA algorithm
	 *RSA only supports
	 *'C-string' (common string)
	 *and the maximum length
	 *is 128 bytes
	 * */
	int i;
	//transform each char (1 bytes) into 2 hexadecimal numbers
	char *plaintext = (char*)malloc(2*lSize+1);
	for(i=0;i<lSize;i++)
	{
		char h=plain_text[i]/16;
		if(h<10)
			h += '0';
		else
			h = h-10+'A';
		char l=plain_text[i]%16;
		if(l<10)
			l += '0';
		else
			l = l-10+'A';
		plaintext[2*i]=h;
		plaintext[2*i+1]=l;
	}
	plaintext[2*lSize]=0;
	/**********************************************************
	now let's test RSA mode!
	**********************************************************/
	//initialize environment
		c_initialize();
		char *public_key, *private_key;

		//RSA1024

	printf("\n\nRSA1024 mode 100 times check\n");

		//generate RSA1024 key
		gen_k1024(&public_key, &private_key);
		printf("plaintext:\n%s\r\n", plaintext);
		printf("RSA1024:\n");
		printf("Public Key:\n%s\n", public_key);
		printf("Private Key:\n%s\n", private_key);

		char *ciphertext;
		char *decrypted;

	for(round=0; round<100; round++){
		clock_gettime(0x01, &start_time);
		//encipher
		ciphertext = encrypt(public_key, plaintext);
		//printf("ciphertext:\n%s\r\n", ciphertext);
		//decipher
		decrypted = decrypt(private_key, ciphertext);
		//printf("deciphered text:\n%s\r\n", decrypted);
		clock_gettime(0x01, &end_time);
		time_elapse[round]=end_time.tv_sec*1000000000.0+end_time.tv_nsec;
		time_elapse[round]=time_elapse[round]-start_time.tv_sec*1000000000.0-start_time.tv_nsec;
		time_elapse[round] /= 1000.0;
		printf("round %d : %.4lf microsec\n", round+1, time_elapse[round]);
	}
	qsort (time_elapse, sizeof(time_elapse)/sizeof(*time_elapse), sizeof(*time_elapse), comparator);

	sum=0;
	for(round=0; round<100; round++){
		sum += time_elapse[round];
	}
	printf("/********************/\n");
	printf("result:\nmedian is : %.4lf microsec and average is :  %.4lf microsec\n", time_elapse[50], sum/100);
	printf("/********************/\n");
	double rsa1024median = time_elapse[50];
	double rsa1024avg = sum/100;


	//digital signature
	char *signature;
	signature = digital_sign(private_key, plaintext);
	printf("RSA digital authentication signature :\n%s\n", signature);
	printf("verify signature, if it is valid then indicating that our program is in good shape!\n\n");
	if (verify_sign(public_key, plaintext, signature)) {
		printf("valid signature!\n");
	} else {
		printf("invalid signature!\n");
	}
	printf("\n\nRSA4096 mode 100 times check\n");
	//RSA4096, the same as above, just change the mode
	gen_k4096(&public_key, &private_key);
	printf("plaintext:\n%s\r\n", plaintext);
	printf("RSA4096:\n");
	printf("Public Key:\n%s\n", public_key);
	printf("Private Key:\n%s\n", private_key);

	for(round=0; round<100; round++){
		clock_gettime(0x01, &start_time);
		ciphertext = encrypt(public_key, plaintext);
		//printf("ciphertext:\n%s\r\n", ciphertext);
		decrypted = decrypt(private_key, ciphertext);
		//printf("deciphered text:\n%s\r\n", decrypted);
		clock_gettime(0x01, &end_time);
		time_elapse[round]=end_time.tv_sec*1000000000.0+end_time.tv_nsec;
		time_elapse[round]=time_elapse[round]-start_time.tv_sec*1000000000.0-start_time.tv_nsec;
		time_elapse[round] /= 1000.0;
		printf("round %d : %.4lf microsec\n", round+1, time_elapse[round]);
	}

	qsort (time_elapse, sizeof(time_elapse)/sizeof(*time_elapse), sizeof(*time_elapse), comparator);

	sum=0;
	for(round=0; round<100; round++){
		sum += time_elapse[round];
	}
	printf("/********************/\n");
	printf("result:\nmedian is : %.4lf microsec and average is :  %.4lf microsec\n", time_elapse[50], sum/100);
	printf("/********************/\n");
	double rsa4096median = time_elapse[50];
	double rsa4096avg = sum/100;


	signature = digital_sign(private_key, plaintext);
	printf("RSA digital authentication signature :\n%s\n", signature);
	printf("verify signature, if it is valid then indicating that our program is in good shape!\n\n");
	if (verify_sign(public_key, plaintext, signature)) {
		printf("valid 4096 signature!\n");
	} else {
		printf("invalid 4096 signature!\n");
	}
	printf("\n");

    //HMAC MD5
	printf("MD5 HMAC 100-time testing: \n");
    int algo = GCRY_MD_MD5;
    char *scheme = "MD5";
    for(round =0; round < 100; round++){
    	clock_gettime(0x01, &start_time);
    	hmac(plaintext, algo, scheme);
    	clock_gettime(0x01, &end_time);
    	time_elapse[round]=end_time.tv_sec*1000000000.0+end_time.tv_nsec;
    	time_elapse[round]=time_elapse[round]-start_time.tv_sec*1000000000.0-start_time.tv_nsec;
    	time_elapse[round] /= 1000.0;
    	printf("round %d : %.4lf microsec\n", round+1, time_elapse[round]);
    }
    qsort (time_elapse, sizeof(time_elapse)/sizeof(*time_elapse), sizeof(*time_elapse), comparator);

    sum=0;
    for(round=0; round<100; round++){
    	sum += time_elapse[round];
    }
    printf("/********************/\n");
    printf("result:\nmedian is : %.4lf microsec and average is :  %.4lf microsec\n", time_elapse[50], sum/100);
    printf("/********************/\n");
    double md5median = time_elapse[50];
    double md5avg = sum/100;

    //HMAC SHA1
    printf("HMAC SHA1 100-time testing: \n");
    algo = GCRY_MD_SHA1;
    scheme = "SHA1";
    for(round =0; round < 100; round++){
    	clock_gettime(0x01, &start_time);
    	hmac(plaintext, algo, scheme);
    	clock_gettime(0x01, &end_time);
    	time_elapse[round]=end_time.tv_sec*1000000000.0+end_time.tv_nsec;
    	time_elapse[round]=time_elapse[round]-start_time.tv_sec*1000000000.0-start_time.tv_nsec;
    	time_elapse[round] /= 1000.0;
    	printf("round %d : %.4lf microsec\n", round+1, time_elapse[round]);
    }
    qsort (time_elapse, sizeof(time_elapse)/sizeof(*time_elapse), sizeof(*time_elapse), comparator);

    sum=0;
    for(round=0; round<100; round++){
    	sum += time_elapse[round];
    }
    printf("/********************/\n");
    printf("result:\nmedian is : %.4lf microsec and average is :  %.4lf microsec\n", time_elapse[50], sum/100);
    printf("/********************/\n");
    double sha1median = time_elapse[50];
    double sha1avg = sum/100;

    //HMAC SHA256
    printf("HMAC SHA256 100-time testing: \n");
    algo = GCRY_MD_SHA256;
    scheme = "SHA256";
    for(round =0; round < 100; round++){
    	clock_gettime(0x01, &start_time);
    	hmac(plaintext, algo, scheme);
    	clock_gettime(0x01, &end_time);
    	time_elapse[round]=end_time.tv_sec*1000000000.0+end_time.tv_nsec;
    	time_elapse[round]=time_elapse[round]-start_time.tv_sec*1000000000.0-start_time.tv_nsec;
    	time_elapse[round] /= 1000.0;
    	printf("round %d : %.4lf microsec\n", round+1, time_elapse[round]);
    }
    qsort (time_elapse, sizeof(time_elapse)/sizeof(*time_elapse), sizeof(*time_elapse), comparator);

    sum=0;
    for(round=0; round<100; round++){
    	sum += time_elapse[round];
    }
    printf("/********************/\n");
    printf("result:\nmedian is : %.4lf microsec and average is :  %.4lf microsec\n", time_elapse[50], sum/100);
    printf("/********************/\n");
    double sha256median = time_elapse[50];
    double sha256avg = sum/100;

    //HMAC SHA256+digital signature
    printf("SHA256 + RSA 4096 testing: \n");
    algo = GCRY_MD_SHA256;
    scheme = "SHA256";
    char *sexp_hmac_sign = "(genkey (rsa (transient-key) (nbits 4:4096)))";
    hmarsa(plaintext, algo, scheme, sexp_hmac_sign);

    printf("result summary:\n");
    printf("For AES128, median is %lf , avg is %lf \n" , aes128median, aes128avg);
    printf("For AES256, median is %lf , avg is %lf \n" , aes256median, aes256avg);
    printf("For RSA1024, median is % lf, avg is %lf \n" , rsa1024median, rsa1024avg);
    printf("For RSA4096, median is %lf , avg is %lf \n" , rsa4096median, rsa4096avg);
    printf("For MD5, median is %lf , avg is %lf \n" , md5median, md5avg);
    printf("For SHA1, median is %lf , avg is %lf \n" , sha1median, sha1avg);
    printf("For SHA256, median is %lf , avg is %lf \n" , sha256median, sha256avg);

    //close file, free memory
	fclose (pFile);
	free (buffer);
	return 0;
}
