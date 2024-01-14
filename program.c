#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/des.h>

typedef unsigned char byte;

#define error(message)\
	printf("ERROR: to %s!\n", message);

#define BUFF_SIZE 1024

void crypt(char *in_filename, char *out_filename, byte *key, byte *iv, byte *inw, byte *outw, int num) {
	FILE *fin = NULL;
	if ((fin = fopen(in_filename, "r")) == NULL) {
		error("open input file");
	}
	FILE *fout = NULL;
	if ((fout = fopen(out_filename, "w")) == NULL) {
		error("open output file");
	}
	
	byte **buff_in;
	buff_in = (byte **)calloc(BUFF_SIZE, sizeof(byte*));
	for (int i = 0; i < BUFF_SIZE; i++)
		buff_in[i] = (byte *)calloc(BUFF_SIZE, sizeof(byte));
	
	int i = 0;
	while (!feof(fin)) {
		fgets(buff_in[i], BUFF_SIZE, fin);
		i++;
	}

	byte **buff_out; 
	buff_out = (byte **)calloc(i, sizeof(byte*));
	for (int k = 0; k < i; k++)
		buff_out[k] = (byte *)calloc(sizeof(byte), strlen(buff_in[k]));	

	for (int c = 0; c < i-1; c++) {
		DES_cblock des_key;
		DES_key_schedule des_key_schedule;
		DES_string_to_key(key, &des_key);
		DES_set_key_checked(&des_key, &des_key_schedule);
		DES_cblock des_iv;
		DES_string_to_key(iv, &des_iv);
		const_DES_cblock des_inw;
		DES_string_to_key(inw, &des_inw);
		const_DES_cblock des_outw;
		DES_string_to_key(outw, &des_outw);
		if (num == 1){
			DES_xcbc_encrypt(buff_in[c], buff_out[c], strlen(buff_in[c]), &des_key_schedule, &des_iv, &des_inw, &des_outw, num);
			DES_cblock des1_key;
			DES_key_schedule des1_key_schedule;
			DES_string_to_key(key, &des1_key);
			DES_set_key_checked(&des1_key, &des1_key_schedule);
			DES_cblock des1_iv;
			DES_string_to_key(iv, &des1_iv);
			int flag = 0;
			byte *cipher = (byte *)calloc(BUFF_SIZE, sizeof(byte));
			DES_ofb64_encrypt(buff_out[c], cipher, strlen(buff_out[c]), &des1_key_schedule, &des1_iv, &flag);
			fputs(cipher, fout);
			fputs("\n", fout);
		}
		else if (num == 0){
			int flag = 0;
			DES_ofb64_encrypt(buff_in[c], buff_out[c], strlen(buff_in[c]), &des_key_schedule, &des_iv, &flag);
			DES_cblock des1_key;
			DES_key_schedule des1_key_schedule;
			DES_string_to_key(key, &des1_key);
			DES_set_key_checked(&des1_key, &des1_key_schedule);
			DES_cblock des1_iv;
			DES_string_to_key(iv, &des1_iv);
			byte *cipher = (byte *)calloc(BUFF_SIZE, sizeof(byte));
			DES_xcbc_encrypt(buff_out[c], cipher, strlen(buff_out[c]), &des1_key_schedule, &des1_iv, &des_inw, &des_outw, num);
			fputs(cipher, fout);
		}
	}
	fclose(fin);
	fclose(fout);
}

byte * digest_message(byte *message, size_t message_length) {
	unsigned int digest_length = MD5_DIGEST_LENGTH;
	byte *digest = (byte *)OPENSSL_malloc(digest_length);
	if (digest == NULL) {
		error("allocate memmory for digest variable \'digest\'");
	}
	MD5_CTX mdctx;
	if (1 != MD5_Init(&mdctx)) {
		error("create message digest context \'mdctx\' and set up digest contenxt \'mdctx\' to use a digest \'type\'");
	}
	if (1 != MD5_Update(&mdctx, message, message_length)) {
		error("hash \'message_length\' bytes of data at \'message\' into the digest context \'mdctx\'");
	}
	if (1 != MD5_Final(digest, &mdctx)){
		error("retrieve the digest value from \'mdctx\' and place it in \'digest\'");
	}
	return digest;
}

void generate_key_and_iv(byte *password, byte **key, byte **iv){
	byte *hash1 = digest_message(password, strlen(password));
	byte *hash2 = digest_message(hash1, strlen(hash1));
	*key = (byte *)malloc(strlen(hash1));
	*iv = (byte *)malloc(strlen(hash2));
	memcpy(*key, hash1, strlen(hash1));
	memcpy(*iv, hash2, strlen(hash2));
}

int main(int argc, char *argv[]) {
	
	if (argc != 5) {
		error("parse arguments, should be:\n[program] [input file name] [output file name] [mone: -e/-d] [password]\nTry again");
	}
	if (strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "-d") == 0) {
		char *in_filename = argv[1], *out_filename = argv[2];
		byte *password = argv[4];
		byte *key = NULL, *iv = NULL;
		byte *inw = "";
		byte *outw = "";
		generate_key_and_iv(password, &key, &iv);
		printf("PASSWORD: %s\n", password);
		printf("KEY:\n");
		BIO_dump_fp(stdout, key, strlen(key));
		printf("IV:\n");
		BIO_dump_fp(stdout, iv, strlen(iv));
		if (strcmp(argv[3], "-e") == 0) {
			crypt(in_filename, out_filename, key, iv, inw, outw, 1);
		} else if (strcmp(argv[3], "-d") == 0) {
			crypt(in_filename, out_filename, key, iv, inw, outw, 0);
		}
	} 
	else {
		error("understand mode, it is incorrect. It should be \'-e\' for encrypt and \'-d\' for decrypt");
	}
	return 0;
}
