#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <string.h>

#define PORT 9999

/*****************************/
/* create openssl context */
/*****************************/
SSL_CTX *create_context()
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_client_method();

  ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

/*****************************/
/* help function to print CN */
/*****************************/
void print_cn_name(const char* label, X509_NAME* const name)
{
  int idx = -1, success = 0;
  unsigned char *utf8 = NULL;

  do
  {
    if (!name) break; /* failed */

    idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (!(idx > -1))  break; /* failed */

    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
    if (!entry) break; /* failed */

    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    if (!data) break; /* failed */

    int length = ASN1_STRING_to_UTF8(&utf8, data);
    if (!utf8 || !(length > 0))  break; /* failed */

    fprintf(stdout, "  %s: %s\n", label, utf8);
    success = 1;

  } while (0);

  if (utf8)
    OPENSSL_free(utf8);

  if (!success)
    fprintf(stdout, "  %s: <not available>\n", label);
}

/*****************************/
/* help function to print SAN */
/*****************************/
void print_san_name(const char* label, X509* const cert)
{
  int success = 0;
  GENERAL_NAMES* names = NULL;
  unsigned char* utf8 = NULL;

  do
  {
    if (!cert) break; /* failed */

    names = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0);
    if (!names) break;

    int i = 0, count = sk_GENERAL_NAME_num(names);
    if (!count) break; /* failed */

    for (i = 0; i < count; ++i)
    {
      GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
      if (!entry) continue;

      if (GEN_DNS == entry->type)
      {
        int len1 = 0, len2 = -1;

        len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
        if (utf8) {
          len2 = (int)strlen((const char*)utf8);
        }

        if (len1 != len2) {
          fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
        }

        /* If there's a problem with string lengths, then     */
        /* we skip the candidate and move on to the next.     */
        /* Another policy would be to fails since it probably */
        /* indicates the client is under attack.              */
        if (utf8 && len1 && len2 && (len1 == len2)) {
          fprintf(stdout, "  %s: %s\n", label, utf8);
          success = 1;
        }

        if (utf8) {
          OPENSSL_free(utf8), utf8 = NULL;
        }
      }
      else
      {
        fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
      }
    }

  } while (0);

  if (names)
    GENERAL_NAMES_free(names);

  if (utf8)
    OPENSSL_free(utf8);

  if (!success)
    fprintf(stdout, "  %s: <not available>\n", label);

}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
  int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
  int err = X509_STORE_CTX_get_error(x509_ctx);
  
  X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
  X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
  
  print_cn_name("Issuer (cn)", iname);
  print_cn_name("Subject (cn)", sname);
  
  if(depth == 0) {
      /* If depth is 0, its the server's certificate. Print the SANs too */
      print_san_name("Subject (san)", cert);
  }
  return preverify;
}

/*****************************/
/* configure openssl context */
/*****************************/
void configure_context(SSL_CTX *ctx) {
  int ret;
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
  // SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_verify_depth(ctx, 10);

  // note: if use CAPATH need to run $ c_rehash . in the folder
  ret = SSL_CTX_load_verify_locations(ctx, "./client-cert/ca-cert.pem", NULL);
  if (ret != 1) {
    printf("Load of certificates failed!: %s", X509_verify_cert_error_string(ERR_get_error()));
  }

  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    /* Set the key and cert */
  // if (SSL_CTX_use_certificate_file(ctx, "./client-cert/client-cert.pem", SSL_FILETYPE_PEM) <= 0) {
  //   fprintf(stderr, "Failure to load certificate\n");
  //   ERR_print_errors_fp(stderr);
  //   exit(1);
  // }

  // if private key is in file system
  // if (SSL_CTX_use_PrivateKey_file(ctx, "./client-cert/client-priv.pem", SSL_FILETYPE_PEM) <= 0) {
  //   fprintf(stderr, "Failure to load private key\n");
  //   ERR_print_errors_fp(stderr);
  //   exit(1);
  // }

  // if private key is stored in TPM2, use OPENSSL Engine
  ENGINE_load_builtin_engines();
  ENGINE* engine = ENGINE_by_id("tpm2tss");
  ENGINE_init(engine);
  UI_METHOD* ui_method = UI_OpenSSL();
  EVP_PKEY* pkey = ENGINE_load_private_key(engine, "./tpm-gen-cert/tpm-client-priv.tss", ui_method, NULL);
  SSL_CTX_use_PrivateKey(ctx, pkey);

  // if private key is stored in TPM2 use this cert
  if (SSL_CTX_use_certificate_file(ctx, "./tpm-gen-cert/tpm-client-cert.pem", SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Failure to load certificate\n");
    ERR_print_errors_fp(stderr);
    exit(1);
  }
}

/*****************************/
/* main function for client */
/*****************************/
int main(int argc, char **argv) {
  int sock;
  struct sockaddr_in serv_addr;
  char buff[256] = {0};
  int ret = 0;
  SSL *ssl;
  SSL_CTX *ctx;
  const SSL_METHOD *method;
  X509_VERIFY_PARAM *param;


  /* init */
  ret = OPENSSL_init_ssl(0, NULL);
  if (!ret) {
    fprintf(stderr, "Failure to init SSL library\n");
    return -1;
  }

  /* create context */
  ctx = create_context();

  /* configure context */
  configure_context(ctx);

  /* open a socket */
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      fprintf(stderr, "Socket creation error\n");
      return -1; 
    }
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) { 
      printf("\nInvalid address/ Address not supported \n"); 
      return -1; 
  }
   
  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { 
    fprintf(stderr, "Connection Failed \n"); 
    return -1; 
  }
  /* create ssl instance from context */
  ssl = SSL_new(ctx);

  param = SSL_get0_param(ssl);

  X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

  ret = X509_VERIFY_PARAM_set1_host(param, "localhost", 0);
  if (ret == 0)
    fprintf(stderr, "X509_VERIFY_PARAM_set1_host() failed \n");

  /* assign socket to ssl instance */
  ret = SSL_set_fd(ssl, sock);
  if (ret == 0)
    fprintf(stderr, "SSL_set_fd() failed\n");

  /* perform ssl handshake & connection */
  ret = SSL_connect(ssl);
  if (ret != 1) {
    fprintf(stderr, "TLS handshake failed ");
    printf("error code %d\n", SSL_get_error(ssl, ret));
  }

  /* for debug purpose check if ssl verify passed or not */
  if ( (ret = SSL_get_verify_result(ssl)) != X509_V_OK ) {
    // 62 - hostname mismatch
    // 18 - self-signed certificate
    // 20 - unable to get local issuer certificate
    // 21 - unable to verify the first certificate
    printf("SSL verify failed %d\n", ret);
  }

  /* perform ssl reads / writes */
  ret = SSL_read(ssl, buff, 255);
  if (ret <= 0)
    fprintf(stderr, "TLS SSL_read failed num = %d \n", ret);

  printf("TLS received data: %s\n", buff);

  /* cleanup */
  close(sock);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  EVP_cleanup();
}