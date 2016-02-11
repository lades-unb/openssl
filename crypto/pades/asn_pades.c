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
#include "bio_lcl.h"
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

		if (!(val = b64_read_asn1_frontend(asnin, it))) {
			ASN1err(ASN1_F_PADES_READ_ASN1, ASN1_R_ASN1_SIG_PARSE_ERROR);
			return NULL;
		}

		BIO_free(asnin);

		return val;
	}
	else 
		if ((bio->method)->type == BIO_TYPE_MEM) {
			asnin = bio;

			/* Check if ASN1 data is base 64, then read and decode ASN1 accordingly */
			if (Pades_ASN1_Data_is_B64((BUF_MEM *) bio->ptr))
				val = b64_read_asn1_frontend(asnin, it);
			else val = ASN1_item_d2i_bio(it, bio, NULL);
			if (!val) {
				ASN1err(ASN1_F_PADES_READ_ASN1, ASN1_R_ASN1_SIG_PARSE_ERROR);
				return NULL;
			}

			return val;
		}
		else {
			ASN1err(ASN1_F_PADES_READ_ASN1, ASN1_R_ILLEGAL_BIO_TYPE);
			return NULL;
		 }
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

/***********************************************************************************************************
*
* This function verifies whether a given byte string contained in 
* the memory buffer "buf" is written in Base 64 format or not.
*
* It uses the "Super Light Regular Expression" (slre) code written
* by Sergey Lyubka, which is freeware.
*
************************************************************************************************************/

int Pades_ASN1_Data_is_B64(BUF_MEM *buf)   {

	// Regular expression that represents Base 64 syntax
	char *b64_regexp = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";

	struct slre	slre;
	struct cap	caps[20];
	int    res = B64_NON_MATCH;


	if (!slre_compile(&slre, b64_regexp)) {
		printf("Error compiling slre: %s\n", slre.err_str);
		return (B64_ERROR);
	}
	
	res = slre_match(&slre, buf->data, buf->length, caps);

	if (res) return (B64_MATCH);
	else     return(B64_NON_MATCH);

}

static BIO * bio_err = NULL;


/***
*   This function takes as input (the cp parameter) a distinguished name in 
*   ASCII format such as: 
*             "/type0=value0/type1=value1/type2=..."
*   and returns an openssl object of type X509_NAME.
*/

X509_NAME *Pades_parse_name(const char *cp, long chtype, int canmulti)
{
	int nextismulti = 0;
	char *work;
	X509_NAME *n;
	char *function_name = "Pades_parse_name()";

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

	if (*cp++ != '/')
		return NULL;

	n = X509_NAME_new();
	if (n == NULL)
		return NULL;
	work = OPENSSL_strdup(cp);
	if (work == NULL)
		goto err;

	while (*cp) {
		char *bp = work;
		char *typestr = bp;
		unsigned char *valstr;
		int nid;
		int ismulti = nextismulti;
		nextismulti = 0;

		// Collect the type 
		while (*cp && *cp != '=')
			*bp++ = *cp++;
		if (*cp == '\0') {
			BIO_printf(bio_err,
				"%s: Hit end of string before finding the equals.\n",
				function_name);
			goto err;
		}
		*bp++ = '\0';
		++cp;

		// Collect the value.
		valstr = (unsigned char *)bp;
		for (; *cp && *cp != '/'; *bp++ = *cp++) {
			if (canmulti && *cp == '+') {
				nextismulti = 1;
				break;
			}
			if (*cp == '\\' && *++cp == '\0') {
				BIO_printf(bio_err,
					"%s: escape character at end of string\n",
					function_name);
				goto err;
			}
		}
		*bp++ = '\0';

		// If not at EOS (must be + or /), move forward.
		if (*cp)
			++cp;

		// Parse 
		nid = OBJ_txt2nid(typestr);
		if (nid == NID_undef) {
			BIO_printf(bio_err, "%s: Skipping unknown attribute \"%s\"\n",
				function_name, typestr);
			continue;
		}
		if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
			valstr, strlen((char *)valstr),
			-1, ismulti ? -1 : 0))
			goto err;
	}

	OPENSSL_free(work);
	return n;

err:
	X509_NAME_free(n);
	OPENSSL_free(work);
	return NULL;
}


/***
*	This function takes as input a distinguished name in ASCII format such as:
*       "/C=BR/ST=SC/L=Brasilia/O=UNB/OU=LADES/CN=Usuario 1"
*   and returns the corresponding ASN1 encoded DN in outbuf.
*/

void Pades_get_ASN1_DN(const char *name, unsigned char **outbuf)
{
	X509_NAME  *x509Name = NULL;

	x509Name = Pades_parse_name(name, MBSTRING_ASC, 1);
	i2d_X509_NAME(x509Name, outbuf);
}


