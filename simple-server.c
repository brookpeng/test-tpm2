#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <string.h>

#define PORT 9999

/*****************************/
/* create socket */
/*****************************/
int create_socket(int port) {
  /* returns a valid socket fd */
  int s;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("Unable to bind");
    exit(EXIT_FAILURE);
  }

  if (listen(s, 1) < 0) {
    perror("Unable to listen");
    exit(EXIT_FAILURE);
  }

  return s;
}

/*****************************/
/* create openssl context */
/*****************************/
SSL_CTX *create_context()
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_server_method();

  ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
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
  ret = SSL_CTX_load_verify_locations(ctx, "./server-cert/ca-cert.pem", NULL);
  if (ret != 1) {
    printf("Load of certificates failed!: %s", X509_verify_cert_error_string(ERR_get_error()));
  }

  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, "./server-cert/server-cert.pem", SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Failure to load certificate\n");
    ERR_print_errors_fp(stderr);
    exit(1);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "./server-cert/server-priv.pem", SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Failure to load private key\n");
    ERR_print_errors_fp(stderr);
    exit(1);
  }
}

/*****************************/
/* close openssl */
/*****************************/
void cleanup_openssl()
{
  EVP_cleanup();
}

/*****************************/
/* main function for server */
/*****************************/
int main(int argc, char **argv) {
  int sock;
  int ret = 0;
  SSL_CTX *ctx;

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
  sock = create_socket(PORT);

  /* Handle connections */
  while(1) {
    struct sockaddr_in addr;
    uint len = sizeof(addr);
    SSL *ssl;
    const char reply[] = "test pass\n";

    int client = accept(sock, (struct sockaddr*)&addr, &len);
    if (client < 0) {
      perror("Unable to accept");
      exit(1);
    }

    /* create ssl instance from context */
    ssl = SSL_new(ctx);

    /* assign socket to ssl intance */
    SSL_set_fd(ssl, client);
    if (ret == 0)
      fprintf(stderr, "SSL_set_fd() failed \n");

    /* perform ssl handshake & connection */
    ret = SSL_accept(ssl);
    if (ret == 0)
      fprintf(stderr, "handshake failed \n");

    /* perform ssl reads / writes */
    ret = SSL_write(ssl, reply, strlen(reply));
    if (ret <= 0) {
      fprintf(stderr, "failed to write ");
      printf("error code %d\n", SSL_get_error(ssl, ret));
    }

    printf("sent num = %d, `%s`", ret, reply);

    /* free ssl instance */
    SSL_shutdown(ssl);
    SSL_free(ssl);

    /* close client connection */
    close(client);
  }
  close(sock);
  SSL_CTX_free(ctx);
  cleanup_openssl();
}