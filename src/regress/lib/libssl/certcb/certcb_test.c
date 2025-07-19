#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

const char *server_cert_file;
const char *server_key_file;

int cert_cb(SSL *ssl, void *arg) {
	if (SSL_use_certificate_file(ssl, server_cert_file, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "[cert_cb] SSL_use_certificate_file failed\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	if (SSL_use_PrivateKey_file(ssl, server_key_file, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "[cert_cb] SSL_use_PrivateKey_file failed\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	return 1;
}

int
main(int argc, char **argv)
{
	SSL_CTX *server_ctx = NULL, *client_ctx = NULL;
	SSL *server_ssl = NULL, *client_ssl = NULL;
	BIO *client_bio = NULL, *server_bio = NULL;
	int ret = 1;

        if (argc != 3) {
                fprintf(stderr, "usage: %s keyfile certfile\n",
			argv[0]);
                exit(1);
        }

        server_key_file = argv[1];
        server_cert_file = argv[2];

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	server_ctx = SSL_CTX_new(TLS_server_method());
	client_ctx = SSL_CTX_new(TLS_client_method());
	if (!server_ctx || !client_ctx)
		goto cleanup;

	server_ssl = SSL_new(server_ctx);
	client_ssl = SSL_new(client_ctx);
	if (!server_ssl || !client_ssl)
		goto cleanup;

	SSL_set_cert_cb(server_ssl, cert_cb, NULL);

	if (!BIO_new_bio_pair(&client_bio, 0, &server_bio, 0)) {
		fprintf(stderr, "BIO_new_bio_pair failed\n");
		goto cleanup;
	}

	SSL_set_bio(server_ssl, server_bio, server_bio);
	SSL_set_bio(client_ssl, client_bio, client_bio);

	SSL_set_accept_state(server_ssl);
	SSL_set_connect_state(client_ssl);

	int server_done = 0, client_done = 0;
	while (!server_done || !client_done) {
		if (!client_done) {
			int r = SSL_do_handshake(client_ssl);
			if (r == 1) client_done = 1;
			else if (SSL_get_error(client_ssl, r) != SSL_ERROR_WANT_READ &&
				 SSL_get_error(client_ssl, r) != SSL_ERROR_WANT_WRITE)
				goto cleanup;
		}
		if (!server_done) {
			int r = SSL_do_handshake(server_ssl);
			if (r == 1) server_done = 1;
			else if (SSL_get_error(server_ssl, r) != SSL_ERROR_WANT_READ &&
				 SSL_get_error(server_ssl, r) != SSL_ERROR_WANT_WRITE)
				goto cleanup;
		}
	}

	X509 *cert = SSL_get_certificate(server_ssl);
	if (cert) {
		printf("SUCCESS: cert_cb worked and handshake succeeded\n");
		ret = 0;
	} else {
		printf("FAIL: SSL_get_certificate() returned NULL\n");
	}

  cleanup:
	if (ret != 0)
		ERR_print_errors_fp(stderr);
	SSL_free(server_ssl);
	SSL_free(client_ssl);
	SSL_CTX_free(server_ctx);
	SSL_CTX_free(client_ctx);
	return ret;
}
