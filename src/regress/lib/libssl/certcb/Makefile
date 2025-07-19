#	$OpenBSD: Makefile,v 1.2 2024/03/20 10:38:05 jsing Exp $

PROG=	certcb_test
LDADD=	-lssl -lcrypto
DPADD=	${LIBSSL} ${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-DLIBRESSL_INTERNAL -Werror

REGRESS_TARGETS= \
	regress-certcb_test

regress-certcb_test: ${PROG}
	./certcb_test \
            ${.CURDIR}/../../libssl/certs/server1-rsa.pem \
            ${.CURDIR}/../../libssl/certs/server1-rsa-chain.pem

.include <bsd.regress.mk>
