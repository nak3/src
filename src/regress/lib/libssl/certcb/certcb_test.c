#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

struct cert_info {
	const char *cert_path;
	const char *key_path;
	const char *who;
};

int
cert_cb(SSL *ssl, void *arg)
{
	struct cert_info *ci = (struct cert_info *)arg;

	fprintf(stderr, "[cert_cb][%s] called with cert: %s, key: %s\n",
	    ci->who, ci->cert_path, ci->key_path);

	if (SSL_use_certificate_chain_file(ssl, ci->cert_path) != 1) {
		fprintf(stderr, "[cert_cb][%s] SSL_use_certificate_file failed\n",
		    ci->who);
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (SSL_use_PrivateKey_file(ssl, ci->key_path, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "[cert_cb][%s] SSL_use_PrivateKey_file failed\n",
		    ci->who);
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
	struct cert_info server_cert, client_cert;
	X509 *srv_cert = NULL, *cli_cert = NULL;
	int ret = 1;
	int server_done = 0, client_done = 0;

	if (argc != 6) {
		fprintf(stderr, "usage: %s server-key.pem server-cert.pem "
		    "client-key.pem client-cert.pem ca-cert.pem\n", argv[0]);
		return 1;
	}

	srv_cert = NULL;
	cli_cert = NULL;

	server_cert.cert_path = argv[2];
	server_cert.key_path = argv[1];
	server_cert.who = "server";

	client_cert.cert_path = argv[4];
	client_cert.key_path = argv[3];
	client_cert.who = "client";

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	if ((server_ctx = SSL_CTX_new(TLS_server_method())) == NULL)
		goto cleanup;
	if ((client_ctx = SSL_CTX_new(TLS_client_method())) == NULL)
		goto cleanup;

	if (!SSL_CTX_load_verify_locations(server_ctx, argv[5], NULL) ||
	    !SSL_CTX_load_verify_locations(client_ctx, argv[5], NULL)) {
		fprintf(stderr, "Failed to load CA cert for verification\n");
		goto cleanup;
	}

	SSL_CTX_set_verify(server_ctx,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);

	if ((server_ssl = SSL_new(server_ctx)) == NULL ||
	    (client_ssl = SSL_new(client_ctx)) == NULL)
		goto cleanup;

	SSL_set_cert_cb(server_ssl, cert_cb, &server_cert);
	SSL_set_cert_cb(client_ssl, cert_cb, &client_cert);

	if (!BIO_new_bio_pair(&client_bio, 0, &server_bio, 0)) {
		fprintf(stderr, "BIO_new_bio_pair failed\n");
		goto cleanup;
	}

	SSL_set_bio(server_ssl, server_bio, server_bio);
	SSL_set_bio(client_ssl, client_bio, client_bio);

	SSL_set_accept_state(server_ssl);
	SSL_set_connect_state(client_ssl);

	while (!server_done || !client_done) {
		if (!client_done) {
			int r = SSL_do_handshake(client_ssl);
			if (r == 1) {
				client_done = 1;
			} else if (SSL_get_error(client_ssl, r) != SSL_ERROR_WANT_READ &&
			    SSL_get_error(client_ssl, r) != SSL_ERROR_WANT_WRITE) {
				goto cleanup;
			}
		}
		if (!server_done) {
			int r = SSL_do_handshake(server_ssl);
			if (r == 1) {
				server_done = 1;
			} else if (SSL_get_error(server_ssl, r) != SSL_ERROR_WANT_READ &&
			    SSL_get_error(server_ssl, r) != SSL_ERROR_WANT_WRITE) {
				goto cleanup;
			}
		}
	}

	srv_cert = SSL_get_certificate(server_ssl);
	cli_cert = SSL_get_peer_certificate(server_ssl);

	if (srv_cert != NULL && cli_cert != NULL) {
		printf("SUCCESS: both cert_cb callbacks worked and handshake succeeded\n");
		ret = 0;
	} else {
		printf("FAIL: cert_cb did not provide certificates correctly\n");
	}

 cleanup:
	if (ret != 0)
		ERR_print_errors_fp(stderr);
	SSL_free(server_ssl);
	SSL_free(client_ssl);
	SSL_CTX_free(server_ctx);
	SSL_CTX_free(client_ctx);

	if (cli_cert != NULL)
		X509_free(cli_cert);

	return ret;
}
