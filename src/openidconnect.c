#include "dynstring.h"
#include "dbg.h"
#include "minisha256.h"

int openidconnect_create_verifyable_string(const char * secret, const char * salt, char ** output) {
	dynstring_context_t str;
	char hash[65];
	int rc;
	rc = dynstring_initialise(&str, 256);
	if (rc) { return -1; }
	rc = dynstring_appendstringz(&str, secret, salt, NULL);
	if (rc) { goto finish; }
	sha256_buf(str.buf, str.pos, hash);
	debug("hash of \"%s\"", dynstring_getcstring(&str));
	debug("is %s", hash);
	dynstring_empty(&str);
	hash[16] = '\0';
	rc = dynstring_appendstringz(&str, salt, ".", hash, NULL);
	if (rc) { goto finish; }
	*output = dynstring_detachcstring(&str);
	return 0;
finish:
	dynstring_free(&str);
	return -1;
}

int openidconnect_verify_string(const char * secret, const char * input) {
	dynstring_context_t str;
	char hash[65];
	char * orighash;
	int rc;
	size_t len;
	rc = dynstring_initialise(&str, 256);
	if (rc) { return -1; }
	dynstring_appendstringz(&str, secret, NULL);
	orighash = strrchr(input, '.');
	if (orighash == NULL) {
		rc = -1;
		goto finish;
	}
	len = orighash - input;
	dynstring_appendstring(&str, input, len);
	sha256_buf(str.buf, str.pos, hash);
	fprintf(stderr, "Hashing [%.*s] %s\n", (int)str.pos, str.buf, hash);
	rc = -1;
	orighash ++;
	if (strncmp(orighash, hash, 16) == 0) {
		rc = 0;
	}
finish:
	dynstring_free(&str);
	return rc;
}

