/* crypto/pades/bio_pades.c */
/*
* Written by Dr Luiz Laranjeira (luiz.laranjeira@gmail.com) for the ITI Pades
* Plugin project.
*/


#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/cms_lcl.h>
#include "pades.h"

/*
*
*  This function reads the contents of a text file 
*  and places them in a BIO mem buffer, returning a 
*  pointer to the created BIO memory buffer.
*
*/

BIO *read_text_file(const char *filename)
{
	int len, byteswritten = 0;
	char linebuf[MAX_SMLEN];
	char eol;

	// Open file
	BIO *biofile = BIO_new_file(filename, "r");
	if (biofile == NULL) {
		printf("Error opening text file\n");
		return(NULL);
	}

	// Create bio mem buffer
	BIO *biomembuf = BIO_new(BIO_s_mem());

	// Read file contents into bio memory buffer
	while ((len = BIO_gets(biofile, linebuf, MAX_SMLEN)) > 0) {
		eol = strip_eol(linebuf, &len);
		if (len) {
			BIO_write(biomembuf, linebuf, len);
			byteswritten += len;
		}
		if (eol) {
			BIO_write(biomembuf, "\r\n", 2);
			byteswritten += 2;
		}
	}
	BIO_set_mem_eof_return(biomembuf, 0);

	return(biomembuf);
}


/*
*
*  This function reads the contents of a BIO mem buffer
*  and places them in a text file. It returns 1 in case
*  of success, and 0 in case of failure.
*
*/

int write_text_file(BIO *biomembuf, const char *filename)
{
	int len, byteswritten = 0;
	char linebuf[MAX_SMLEN];
	char eol;
	int ret = 0;

	// Open file
	BIO *biofile = BIO_new_file(filename, "w");
	if (biofile == NULL) {
		printf("Error opening text file\n");
		return(ret);
	}


	// Read the memory buffer contents and write them into the file
	while ((len = BIO_gets(biomembuf, linebuf, MAX_SMLEN)) > 0) {
		eol = strip_eol(linebuf, &len);
		if (len) {
			BIO_write(biofile, linebuf, len);
			byteswritten += len;
		}
		if (eol) {
			BIO_write(biofile, "\r\n", 2);
			byteswritten += 2;
		}
	}

	ret = 1;
	return(ret);
}


int strip_eol(char *linebuf, int *plen)
{
	int len = *plen;
	char *p, c;
	int is_eol = 0;
	p = linebuf + len - 1;
	for (p = linebuf + len - 1; len > 0; len--, p--) {
		c = *p;
		if (c == '\n')
			is_eol = 1;
		else if (c != '\r')
			break;
	}
	*plen = len;
	return is_eol;
}

