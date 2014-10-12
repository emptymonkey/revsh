
/***********************************************************************************************************************
 *
 *	in_the_key_of_c
 *
 *	emptymonkey's tool for converting RSA key pairs into C source code representations.
 *
 *	2014-10-12
 *
 **********************************************************************************************************************/



#define _XOPEN_SOURCE 500



#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>



char *program_invocation_short_name = NULL;



void usage(){
	fprintf(stderr, "\nusage(): %s [-k KEY_FILE] [-c CERT_FILE [-f]]\n\n", program_invocation_short_name);
	fprintf(stderr, "\t-k\tPrint the C code equivalent of the RSA KEY_FILE in DER format.\n");
	fprintf(stderr, "\t-c\tPrint the C code equivalent of RSA CERT_FILE in DER format.\n");
	fprintf(stderr, "\t-f\tPrint the C code equivalent of the SHA1 fingerprint for CERT_FILE.\n");
	fprintf(stderr, "\n\tNote: At least one of the two options, -k or -c, must be present.\n");
	fprintf(stderr, "\n");
	
	exit(-1);
}



int main(int argc, char **argv){

	int opt;

	int i;
	unsigned int j;

	char *key_path = NULL, *cert_path = NULL;
	char *key_short_name, *cert_short_name;
	int key_len, cert_len;

	char *tmp_char_ptr;

	FILE *key_stream;
	RSA *key;

	FILE *cert_stream;
	X509 *cert;

	unsigned char *buffer_head, *buffer_ptr;
	int buffer_len;	

	int do_fingerprint = 0;
	const EVP_MD *digest;
	unsigned char fingerprint[EVP_MAX_MD_SIZE];
	unsigned int fingerprint_len;


	/* We set our own program_invocation_short_name here for portability. */	
	if((program_invocation_short_name = strrchr(argv[0], '/'))){
		program_invocation_short_name++;
	}else{
		program_invocation_short_name = argv[0];
	}


	while((opt = getopt(argc, argv, "k:c:fh")) != -1){
		switch(opt){

			case 'k':
				key_path = optarg;
				break;

			case 'c':
				cert_path = optarg;
				break;
		
			case 'f':
				do_fingerprint = 1;
			break;

			case 'h':
			default:
				usage();
		}
	}

	if(!key_path && !cert_path){
		usage();
	}

	if(do_fingerprint && !cert_path){
		usage();
	}


	SSL_load_error_strings();
	SSL_library_init();


	/* OpenSSL isn't very good at checking buffer sizes or telling you how big they should be. */
	/* We will grab a pages worth and cross our fingers. /sigh */
	buffer_len = getpagesize();
	if((buffer_head = (unsigned char *) calloc(buffer_len, sizeof(char))) == NULL){
		fprintf(stderr, "%s: calloc(%d, %d): %s\n", 
				program_invocation_short_name, \
				buffer_len, (int) sizeof(char), \
				strerror(errno));
		exit(-1);
	}


	/* Set up the private key structures. */
	if(key_path){

		if((tmp_char_ptr = strrchr(key_path, '/'))){
			tmp_char_ptr++;
		}else{
			tmp_char_ptr = key_path;
		}

		if((key_short_name = (char *) calloc(strlen(tmp_char_ptr) + 1, sizeof(char))) == NULL){
			fprintf(stderr, "%s: calloc(%d, %d): %s\n", 
					program_invocation_short_name, \
					(int) strlen(tmp_char_ptr) + 1, (int) sizeof(char), \
					strerror(errno));
			exit(-1);
		}

		memcpy(key_short_name, tmp_char_ptr, strlen(tmp_char_ptr));
		if((tmp_char_ptr = strrchr(key_short_name, '.'))){
			*tmp_char_ptr = '\0';
		}

		if((key_stream = fopen(key_path, "r")) == NULL){
			fprintf(stderr, "%s: fopen(%s, \"r\"): %s\n", 
					program_invocation_short_name, \
					key_path, \
					strerror(errno));
			exit(-1);
		}

		if((key = PEM_read_RSAPrivateKey(key_stream, NULL, NULL, NULL)) == NULL){
			fprintf(stderr, "%s: PEM_read_RSAPrivateKey(%lx, NULL, NULL, NULL): %s\n", 
					program_invocation_short_name, \
					(unsigned long) key_stream, \
					strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		fclose(key_stream);

		buffer_ptr = buffer_head;
		if(!(key_len = i2d_RSAPrivateKey(key, &buffer_ptr))){
			fprintf(stderr, "%s: i2d_RSAPrivateKey(%lx, %lx): %s\n", 
					program_invocation_short_name, \
					(unsigned long) key, (unsigned long) buffer_ptr, \
					strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		printf("\nunsigned char %s[%d]={\n", key_short_name, key_len);
		for(i = 0; i < key_len; i++){
			if(i && !(i % 16)){
				printf("\n");
			}
			printf("0x%02X,", buffer_head[i]);
		}
		printf("\n};\n");
	}


	/* Set up the public certificate structures. */
	if(cert_path){

		if((tmp_char_ptr = strrchr(cert_path, '/'))){
			tmp_char_ptr++;
		}else{
			tmp_char_ptr = cert_path;
		}

		if((cert_short_name = (char *) calloc(strlen(tmp_char_ptr) + 1, sizeof(char))) == NULL){
			fprintf(stderr, "%s: calloc(%d, %d): %s\n",
					program_invocation_short_name, \
					(int) strlen(tmp_char_ptr) + 1, (int) sizeof(char), \
					strerror(errno));
			exit(-1);
		}

		memcpy(cert_short_name, tmp_char_ptr, strlen(tmp_char_ptr));
		if((tmp_char_ptr = strrchr(cert_short_name, '.'))){
			*tmp_char_ptr = '\0';
		}

		if((cert_stream = fopen(cert_path, "r")) == NULL){
			fprintf(stderr, "%s: fopen(%s, \"r\"): %s\n",
					program_invocation_short_name, \
					cert_path, \
					strerror(errno));
			exit(-1);
		}

		if((cert = PEM_read_X509(cert_stream, NULL, NULL, NULL)) == NULL){
			fprintf(stderr, "%s: PEM_read_X509(%lx, NULL, NULL, NULL): %s\n",
					program_invocation_short_name, \
					(unsigned long) cert_stream, \
					strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}
		fclose(cert_stream);

		/* Don't forget to generate the fingerprint if it's requested. */
		if(do_fingerprint){
			digest = EVP_sha1();

			if(!X509_digest(cert, digest, fingerprint, &fingerprint_len)){
				fprintf(stderr, "%s: !X509_digest(%lx, %lx, %lx, %lx): %s\n",
						program_invocation_short_name, \
						(unsigned long) cert, (unsigned long) digest, (unsigned long) fingerprint, (unsigned long) &fingerprint_len, \
						strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			printf("\nchar *%s_fingerprint = \"", cert_short_name);

			/* For some reason, openssl outputs C code as uppercase hex letters, but fingerprints are lowercase. ?? */
			for(j = 0; j < fingerprint_len; j++){
				printf("%02x", fingerprint[j]);
			}
			printf("\";\n");

			return(0);
		}

		buffer_ptr = buffer_head;
		if(!(cert_len = i2d_X509(cert, &buffer_ptr))){
			fprintf(stderr, "%s: i2d_X509(%lx, %lx): %s\n",
					program_invocation_short_name, \
					(unsigned long) cert, (unsigned long) buffer_ptr, \
					strerror(errno));
				ERR_print_errors_fp(stderr);
			exit(-1);
		}

		printf("\nunsigned char %s[%d]={\n", cert_short_name, cert_len);

		for(i = 0; i < cert_len; i++){
			if(i && !(i % 16)){
				printf("\n");
			}
			printf("0x%02X,", buffer_head[i]);
		}
		printf("\n};\n");
	}

	return(0);
}
