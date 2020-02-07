#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#define READ_SIZE 32768
#define KEY_HANDLE "/home/dwang3/Desktop/tls-tpm/tpm-gen-cert/tpm-client-priv.tss"

static int rsa_engine_init(const char *engine_id, ENGINE **pe) {
	int ret;
	ENGINE *e;

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id(engine_id);
	if (!e) {
		fprintf(stderr, "Engine isn't available\n");
		ret = -1;
		goto err_engine_by_id;
	}

	if (!ENGINE_init(e)) {
		fprintf(stderr, "Couldn't initialize engine\n");
		ret = -1;
		goto err_engine_init;
	}

	if (!ENGINE_set_default_RSA(e)) {
		fprintf(stderr, "Couldn't set engine as default for RSA\n");
		ret = -1;
		goto err_set_rsa;
	}

	*pe = e;
	return 0;

err_set_rsa:
	ENGINE_finish(e);
err_engine_init:
	ENGINE_free(e);
err_engine_by_id:
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x02070000fL)
	ENGINE_cleanup();
#endif
	return ret;
}

static int openssl_init() {
	int ret;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x02070000fL)
	ret = SSL_library_init();
#else
	ret = OPENSSL_init_ssl(0, NULL);
#endif
	if (!ret) {
		fprintf(stderr, "Failure to init SSL library\n");
		return -1;
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x02070000fL)
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();
#endif
	return 0;
}

static int is_filename(char *name) {
	if (access(name, F_OK) != -1)
		return 1;
	else
		return 0;
}

int rsa_sign_with_key(RSA *rsa, char *filename, uint8_t **sigp, uint *sig_len) {
	EVP_PKEY *key;
	EVP_MD_CTX *context;
	int size = 0;
	char *buffer = NULL;
	int byte_read = 0;
	uint8_t *sig = NULL;

	key = EVP_PKEY_new();
	if (!key) {
		fprintf(stderr, "Failure creating EVP_PKEY object\n");
		return 1;
	}

	if (!EVP_PKEY_set1_RSA(key, rsa)) {
		fprintf(stderr, "EVP key setup failed\n");
		goto err_set;
	}

	size = EVP_PKEY_size(key);
	sig = malloc(size);
	if (!sig) {
		fprintf(stderr, "Couldn't allocate memory for signature (%d bytes)\n", size);
		goto err_alloc;
	}

	context = EVP_MD_CTX_create();
	if (!context) {
		fprintf(stderr, "Couldn't create EVP context\n");
		goto err_create;
	}

	if (!EVP_SignInit(context, EVP_sha256())) {
		fprintf(stderr, "Failed to setup signer\n");
		goto err_sign;
	}

	FILE *file = fopen(filename, "rb");
	if (!file) {
		fprintf(stderr, "Couldn't open file (%s)\n", filename);
		goto err_sign;
	}
	buffer = malloc(READ_SIZE);
	if (!buffer) {
		fprintf(stderr, "Couldn't allow buffer for reading file\n");
		goto err_sign;
	}

	while (byte_read = fread(buffer, 1, READ_SIZE, file)) {
		if(!EVP_SignUpdate(context, buffer, byte_read)) {
			fprintf(stderr, "Failed to update signer\n");
			goto err_clean;
		}
	}

	if (!EVP_SignFinal(context, sig, sig_len, key)) {
		fprintf(stderr, "Couldn't obtain signature\n");
		goto err_clean;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x02070000fL)
	EVP_MD_CTX_cleanup(context);
#else
	EVP_MD_CTX_retset(context);
#endif
	fclose(file);
	EVP_MD_CTX_destroy(context);
	EVP_PKEY_free(key);
	*sigp = sig;
	return 0;

err_clean:
	free(buffer);
err_sign:
	fclose(file);
	EVP_MD_CTX_destroy(context);
err_create:
	free(sig);
err_alloc:
err_set:
	EVP_PKEY_free(key);
	return 1;
}

int rsa_sign(char *filename, uint8_t **sigp, uint *sig_len) {
	int ret;
	ENGINE *e = NULL;
	EVP_PKEY *key;
	RSA *rsa;

	ret = rsa_engine_init("tpm2tss", &e);
	if (ret)
		return 1;

	key = ENGINE_load_private_key(e, KEY_HANDLE, NULL, NULL);
	if (!key) {
		fprintf(stderr, "Failure loading private key from engine\n");
		return 1;
	}
	rsa = EVP_PKEY_get1_RSA(key);
	if (!rsa) {
		fprintf(stderr, "Couldn't convert to private key RSA style key\n");
		goto err_rsa;
	}

	if (rsa_sign_with_key(rsa, filename, sigp, sig_len)) {
		goto err_rsa;
	}

	EVP_PKEY_free(key);
	RSA_free(rsa);
	ENGINE_finish(e);
	ENGINE_free(e);
	return 0;

err_rsa:
	EVP_PKEY_free(key);
	RSA_free(rsa);
	ENGINE_finish(e);
	ENGINE_free(e);
	return 1;
}

int write_to_file(char *originfile, unsigned char *base64, unsigned int size) {
	int ret;
	FILE *file;
	char *sig_filepath, *sign_filename; 

	sig_filepath = strdup(originfile);
	sign_filename = basename(sig_filepath);
	strncat(sign_filename, ".sig", 4);
	// printf("%s", sign_filename);

	file = fopen(sign_filename, "wb");
	if (!file) {
		fprintf(stderr, "Couldn't create file (%s)\n", sign_filename);
		goto err_clean;
	}
	ret = fwrite(base64, size, 1, file);
	if (!ret) {
		fprintf(stderr, "Couldn't write file (%s)\n", sign_filename);
		goto err_close;
	}
	// ret = fwrite("\n", 1, 1, file);

	free(sig_filepath);
	fclose(file);
	return 0;

err_close:
	fclose(file);
err_clean:
	free(sig_filepath);
	return 1;
}

/*****************************/
/* main function for sign */
/*****************************/
int main(int argc, char **argv) {
	uint8_t *sig;
	uint sig_len;
	unsigned char *base64;
	unsigned int base64_len;
	int ret;

	if (argc  != 2) {
		fprintf(stderr, "Incorrect number of arguments\n");
		return 1;
	}
	if (openssl_init()) {
		return 1;
	}

	if (is_filename(argv[1])){

		ret = rsa_sign(argv[1], &sig, &sig_len);
		if (ret) {
			return 1;
		}

		base64_len = (((sig_len + 2 ) / 3) * 4) + 1;
		base64 = malloc(base64_len);
		if (!base64) {
			fprintf(stderr, "Couldn't allocate memory for encoder\n");
			goto err_sig;
		}
		ret = EVP_EncodeBlock(base64, sig, sig_len);
		if (!ret) {
			fprintf(stderr, "Couldn't encode signature\n");
			goto err_clean;
		}
		base64[base64_len-1] = '\n';
		printf("base64: %s\n", base64);
		ret = write_to_file(argv[1], base64, base64_len);
		if (!ret) {
			goto err_clean;
		}
	}
	else {
		fprintf(stderr, "%s no such file can be found\n", argv[1]);
		return 1;
	}

	free(base64);
	free(sig);
	return 0;

err_clean:
	free(base64);
err_sig:
	free(sig);
}
