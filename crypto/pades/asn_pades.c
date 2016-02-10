/* crypto/asn1/asn_pades.c */
/*
* Written by Dr Luiz Laranjeira (luiz.laranjeira@gmail.com) for the ITI Pades
* Plugin project.
*/

#include <stdio.h>
#include <ctype.h>
#include "cryptlib.h"
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/asn1.h>
#include "pades.h"


ASN1_VALUE *PADES_read_ASN1(BIO *bio, const ASN1_ITEM *it)
{
	BIO *asnin;
	ASN1_VALUE *val;

	if ((bio->method)->type == BIO_TYPE_FILE) {

		int len, byteswritten = 0;
		char linebuf[MAX_SMLEN];
		char eol;

		asnin = BIO_new(BIO_s_mem());
		while ((len = BIO_gets(bio, linebuf, MAX_SMLEN)) > 0) {
			eol = strip_eol(linebuf, &len);
			if (len) {
				BIO_write(asnin, linebuf, len);
				byteswritten += len;
			}
			if (eol) {
				BIO_write(asnin, "\r\n", 2);
				byteswritten += 2;
			}
		}
		BIO_set_mem_eof_return(asnin, 0);
	}
	else if ((bio->method)->type == BIO_TYPE_MEM) asnin = bio;
	else {
		ASN1err(ASN1_F_PADES_READ_ASN1, ASN1_R_ILLEGAL_BIO_TYPE);
		return NULL;
	}

	/* Read in ASN1 */
	if (!(val = b64_read_asn1_frontend(asnin, it))) {
		ASN1err(ASN1_F_PADES_READ_ASN1, ASN1_R_ASN1_SIG_PARSE_ERROR);
		return NULL;
	}

	if ((bio->method)->type == BIO_TYPE_FILE)
		BIO_free(asnin);

	return val;
}

int PADES_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
	int ctype_nid, int econt_nid,
	STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it)
{
	if ((flags & SMIME_DETACHED) && data) {

		// This is a trick to avoid that the data contents (data that has been signed)
		// be output to the output BIO. The flag PKCS7_NOSMIMECAP, no SMIME capabilities,
		// is here used for the implementation of the PADES digital signature, for which
		// we want the output BIO to receive only the CMS object in B64 format.
		if (flags & PKCS7_NOSMIMECAP) {
			BIO *tmpout = BIO_new(BIO_s_null());
			if (!asn1_output_data_frontend(tmpout, data, val, flags, it))
				return 0;
			BIO_free(tmpout);
		}
		else
			if (!asn1_output_data_frontend(bio, data, val, flags, it))
				return 0;

		long num1, num2 = bio->num_write;

		B64_write_ASN1_frontend(bio, val, NULL, 0, it);
		
		// Flush it wrote to a file.
		if (!(flags & PKCS7_NOSMIMECAP)) fflush((FILE *)bio->ptr);

		num1 = bio->num_write - num2;
		//printf("O conteudo ASN1 (assinatura) contem %ld bytes (prev = %ld)\n", num1, num2);

		return 1;
	}

	if (!B64_write_ASN1_frontend(bio, val, data, flags, it))
		return 0;

	return 1;
}
