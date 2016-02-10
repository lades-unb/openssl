/* crypto/cms/cms_pades.c */
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
#include <openssl/cms_lcl.h>
#include "pades.h"



int PADES_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data, int flags)
{
	STACK_OF(X509_ALGOR) *mdalgs;
	int ctype_nid = OBJ_obj2nid(cms->contentType);
	int econt_nid = OBJ_obj2nid(CMS_get0_eContentType(cms));
	if (ctype_nid == NID_pkcs7_signed)
		mdalgs = cms->d.signedData->digestAlgorithms;
	else
		mdalgs = NULL;

	return PADES_write_ASN1(bio, (ASN1_VALUE *)cms, data, flags,
		ctype_nid, econt_nid, mdalgs,
		ASN1_ITEM_rptr(CMS_ContentInfo));
}

CMS_ContentInfo *PADES_read_CMS(BIO *bio)
{
	return (CMS_ContentInfo *)PADES_read_ASN1(bio, ASN1_ITEM_rptr (CMS_ContentInfo));
}




/***************************************

// ESTE CÓDIGO ESTÁ AQUI APENAS PARA NÃO SE PERDER O CONHECIMENTO DE ALGUNS STATEMENTS

// READ SIGNATURE IN ASN1 FORMAT FROM FILE INTO BIO MEMORY BUFFER
int len, byteswritten = 0;
size_t i;
char linebuf[MAX_SMLEN];
char eol;
BIO *asnin;

asnin = BIO_new(BIO_s_mem());
while ((len = BIO_gets(in, linebuf, MAX_SMLEN)) > 0) {
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
BIO_write(asnin, "\r\n", 2);
byteswritten += 2;
BIO_set_mem_eof_return(asnin, 0);

printf("Will print ASN1 contents in Verifier_Test main():\n\n");
BUF_MEM *asnbuf = (BUF_MEM *)asnin->ptr;
for (i = 0; i < asnbuf->length; i++) printf("%c", asnbuf->data[i]);
printf("\nFinished printing ASN1 contents (%d chars, byteswritten = %d).\n\n", asnbuf->length, byteswritten);

//BUF_MEM *buf = (BUF_MEM *)asnin->ptr;
//const unsigned char *p = (const unsigned char *)buf->data;
//cms = (CMS_ContentInfo *) ASN1_item_d2i(NULL, &p, byteswritten, ASN1_ITEM_rptr(CMS_ContentInfo));

cms = (CMS_ContentInfo *) b64_read_asn1_frontend(asnin, ASN1_ITEM_rptr(CMS_ContentInfo));


//BUF_MEM *ctbuf = (BUF_MEM *)dcont->ptr;
//printf("Will print contents file in Verifier_Test main():\n\n");
//for (i = 0; i < ctbuf->length; i++) printf("%c", ctbuf->data[i]);
//printf("\nFinished printing contents file (%d chars).\n\n", ctbuf->length);

// File to output verified content to 
//out = BIO_new_file("../Debug/smver.txt", "w");
//if (!out)
//    goto err;

******************************/
