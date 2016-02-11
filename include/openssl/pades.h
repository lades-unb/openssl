/* crypto/pades/pades.h */
/*
* Written by Dr Luiz Laranjeira (luiz.laranjeira@gmail.com) for the ITI Pades
* Plugin project.
*/


#ifndef HEADER_PADES_H
# define HEADER_PADES_H

#include <stdio.h>
#include <ctype.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/cms.h>

#include "slre.h"

#ifdef  __cplusplus
extern "C" {
#endif


#define MAX_SMLEN 1024


OPENSSL_EXTERN CMS_ContentInfo *PADES_read_CMS(BIO *bio);

int PADES_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data, int flags);

ASN1_VALUE *PADES_read_ASN1(BIO *bio, const ASN1_ITEM *it);
int PADES_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
	int ctype_nid, int econt_nid,
	STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it);

BIO *read_text_file(const char *filename);
int write_text_file(BIO *biomembuf, const char *filename);
int strip_eol(char *linebuf, int *plen);

int Pades_ASN1_Data_is_B64(BUF_MEM *buf);

X509_NAME *Pades_parse_name(const char *cp, long chtype, int canmulti);

void Pades_get_ASN1_DN(const char *name, unsigned char **outbuf);


#ifdef  __cplusplus
}
#endif
#endif
