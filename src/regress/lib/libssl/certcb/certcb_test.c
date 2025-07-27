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
	int simulate_lookup_delay;
	int called;
};

int
cert_cb(SSL *ssl, void *arg)
{
	struct cert_info *ci = (struct cert_info *)arg;

	fprintf(stderr, "[cert_cb][%s] called (called=%d)\n", ci->who, ci->called);

	if (ci->simulate_lookup_delay && ci->called++ == 0) {
		fprintf(stderr, "[cert_cb][%s] called (called=%d)\n", ci->who, ci->called);
		return -1; /* simulate deferred lookup */
	}

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
run_test(const char *server_key, const char *server_cert,
    const char *client_key, const char *client_cert,
    const char *ca_cert, int use_lookup_delay)
{
	SSL_CTX *server_ctx = NULL, *client_ctx = NULL;
	SSL *server_ssl = NULL, *client_ssl = NULL;
	BIO *client_bio = NULL, *server_bio = NULL;
	struct cert_info server_cert_info, client_cert_info;
	X509 *srv_cert = NULL, *cli_cert = NULL;
	int ret = 1;
	int server_done = 0, client_done = 0;

	server_cert_info.cert_path = server_cert;
	server_cert_info.key_path = server_key;
	server_cert_info.who = "server";
	server_cert_info.simulate_lookup_delay = use_lookup_delay;
	server_cert_info.called = 0;

	client_cert_info.cert_path = client_cert;
	client_cert_info.key_path = client_key;
	client_cert_info.who = "client";
	client_cert_info.simulate_lookup_delay = use_lookup_delay;
	client_cert_info.called = 0;

	if ((server_ctx = SSL_CTX_new(TLS_server_method())) == NULL)
		goto cleanup;
	if ((client_ctx = SSL_CTX_new(TLS_client_method())) == NULL)
		goto cleanup;

	if (!SSL_CTX_load_verify_locations(server_ctx, ca_cert, NULL) ||
	    !SSL_CTX_load_verify_locations(client_ctx, ca_cert, NULL)) {
		fprintf(stderr, "Failed to load CA cert for verification\n");
		goto cleanup;
	}

	SSL_CTX_set_verify(server_ctx,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);

	if ((server_ssl = SSL_new(server_ctx)) == NULL ||
	    (client_ssl = SSL_new(client_ctx)) == NULL)
		goto cleanup;

	SSL_set_cert_cb(server_ssl, cert_cb, &server_cert_info);
	SSL_set_cert_cb(client_ssl, cert_cb, &client_cert_info);

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
				printf("@@@ client done\n");
				fprintf(stderr, "[client done]\n");
			} else {
				int err = SSL_get_error(client_ssl, r);
				printf("@@@ client err = %d\n", err);
				if (err != SSL_ERROR_WANT_READ &&
				    err != SSL_ERROR_WANT_WRITE &&
				    err != SSL_ERROR_WANT_X509_LOOKUP)
					goto cleanup;
			}
		}
		if (!server_done) {
			int r = SSL_do_handshake(server_ssl);
			if (r == 1) {
				server_done = 1;
				printf("@@@ server done\n");
				fprintf(stderr, "[server done]\n");
			} else {
				int err = SSL_get_error(server_ssl, r);
				printf("@@@ server err = %d\n", err);
				if (err != SSL_ERROR_WANT_READ &&
				    err != SSL_ERROR_WANT_WRITE &&
				    err != SSL_ERROR_WANT_X509_LOOKUP)
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
	printf("@@@ cleanup\n");
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

int
main(int argc, char **argv)
{
	int failed = 0;
	if (argc != 6) {
		fprintf(stderr, "usage: %s server-key.pem server-cert.pem "
		    "client-key.pem client-cert.pem ca-cert.pem\n", argv[0]);
		return 1;
	}

	printf("[TEST] Normal cert_cb execution\n");
	failed |= run_test(argv[1], argv[2], argv[3], argv[4], argv[5], 0);

	printf("\n[TEST] Deferred cert_cb (SSL_ERROR_WANT_X509_LOOKUP)\n");
	failed |= run_test(argv[1], argv[2], argv[3], argv[4], argv[5], 1);

	return failed;
}
