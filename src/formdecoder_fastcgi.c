#include <fcgiapp.h>
#include "errorinfo.h"
#include "formdecoder.h"
#include "formdecoder_fastcgi.h"
#include "simplemap.h"
#include "querystring.h"

#define READ_BUFFER_SIZE 8192
// This will write the posted data to a file, see below
#define FORMDECODER_WRITEPOSTEDDATA

struct formdecoder_context {
	int type;

	simplemap_context * fields;
	struct formdecoder_context_field * current_field;

	dynstring_context_t current_field_data;
	char * buf;
	querystring_context * qsctx;
	int save_files;
};

static int formdecoder_decodefcgirequest_multipart(FCGX_Request * req, formdecoder_context ** fd_ctx_ptr, size_t max_size, errorinfo_context ** ei_ctx_ptr) {
	mimedecoder_context * mi_ctx = NULL;
	formdecoder_context * fd_ctx = NULL;
	char * content_type;
	char * read_buffer;
	size_t bytes_read, bytes_read_total;
	int rc;
#ifdef FORMDECODER_WRITEPOSTEDDATA
	FILE * file;
	file = fopen("/tmp/formdecoder-postdata.tmp", "w");
	if (file == NULL) {
		debug("could not create full post output file (/tmp/formdecoder-postdata.tmp)");
		return -1;
	}
#endif /* FORMDECODER_WRITEPOSTEDDATA */
	fd_ctx = formdecoder_init();
	if (fd_ctx == NULL) {
		goto error_none;
	}
	fd_ctx->save_files = 1;
	mi_ctx = mimedecoder_initsimple();
	if (mi_ctx == NULL) {
		goto error_fd;
	}
	mi_ctx->max_size = max_size;
	content_type = FCGX_GetParam("CONTENT_TYPE", req->envp);
	rc = mimedecoder_setcontenttype(mi_ctx, content_type);
	if (rc) {
		errorinfo_createbasic(ei_ctx_ptr, "mimedecoder_setcontenttype() %d", rc);
		goto error_mi;
	}
	mi_ctx->state = MIMED_STATE_BODY_LF_SEEN;
	mi_ctx->user_context = fd_ctx;
	mi_ctx->callback = (mimedecoder_callback_fn)&formdecoder_mimedecoder_callback;
	read_buffer = malloc(READ_BUFFER_SIZE);
	if (read_buffer == NULL) {
		goto error_mi;
	}
	bytes_read_total = 0;
	do {
		bytes_read = FCGX_GetStr(read_buffer, READ_BUFFER_SIZE, req->in);
		if (bytes_read) {
#ifdef FORMDECODER_WRITEPOSTEDDATA
			rc = fwrite(read_buffer, 1, bytes_read, file);
			debug("writeposteddata fwrite() %d", rc);
#endif /* FORMDECODER_WRITEPOSTEDDATA */
			rc = mimedecoder_decode(mi_ctx, read_buffer, bytes_read);
			if (rc) {
				/*
				if (mi_ctx->substate == MIMEDECODER_SUBSTATE_ERROR_CONTENTTOOLARGE) {
					errorinfo_createbasic(ei_ctx_ptr, "MIMEDECODER_SUBSTATE_ERROR_CONTENTTOOLARGE rc = %d", rc);
				} else
				if (mi_ctx->substate == MIMEDECODER_SUBSTATE_ERROR_UNKNOWN) {
					errorinfo_createbasic(ei_ctx_ptr, "MIMEDECODER_SUBSTATE_ERROR_UNKNOWN rc = %d", rc);
				} else {
					errorinfo_createbasic(ei_ctx_ptr, "MIMEDECODER_SUBSTATE_ERROR_%d rc = %d", mi_ctx->substate, rc);
				}
				*/
				goto error_rb;
			}
			bytes_read_total += bytes_read;
		}
	} while (bytes_read > 0);
#ifdef FORMDECODER_WRITEPOSTEDDATA
	fclose(file);
#endif /* FORMDECODER_WRITEPOSTEDDATA */
#ifdef FORMDECODER_PRINTFIELDNAMES
	debug("formdecoder_fieldcount(fd_ctx) %d", (int)formdecoder_fieldcount(fd_ctx));
#endif /* FORMDECODER_PRINTFIELDNAMES */
	free(read_buffer);
	read_buffer = NULL;
	rc = mimedecoder_finalise(mi_ctx);
	mi_ctx = NULL;
	if (rc) {
		goto error_fd;
	}
	*fd_ctx_ptr = fd_ctx;
	return 0;
error_rb:
	free(read_buffer);
error_mi:
	mimedecoder_dispose(mi_ctx);
error_fd:
	formdecoder_dispose(fd_ctx);
error_none:
#ifdef FORMDECODER_WRITEPOSTEDDATA
	fclose(file);
#endif /* FORMDECODER_WRITEPOSTEDDATA */
	return -1;
}

static int formdecoder_decodefcgirequest_urlencoded(FCGX_Request * req, formdecoder_context ** fd_ctx_ptr, size_t max_size, errorinfo_context ** ei_ctx_ptr) {
	formdecoder_context * fd_ctx = NULL;
	char * read_buf;
	size_t bytes_read, bytes_read_total;
	size_t bytes_to_read;
	fd_ctx = formdecoder_init();
	if (fd_ctx == NULL) {
		return -1;
	}
	fd_ctx->type = FORMDECODER_QUERYSTRING;
	read_buf = malloc(max_size);
	if (read_buf == NULL) {
		goto error_fd;
	}
	bytes_read_total = 0;
	/* read all the bytes into the buffer */
	do {
		bytes_to_read = max_size - bytes_read_total;
		if (bytes_to_read == 0) {
			errorinfo_createbasic(ei_ctx_ptr, "read buffer full");
			goto error_rb;
		}
		bytes_read = FCGX_GetStr(read_buf + bytes_read_total, bytes_to_read, req->in);
		if (bytes_read) {
			/* do some decoding of the read buffer */
			bytes_read_total += bytes_read;
		}
	} while (bytes_read > 0);
	if (bytes_read_total >= max_size) {
		goto error_rb;
	}
	read_buf[bytes_read_total] = '\0';
	fd_ctx->qsctx = querystring_decode_inplace(read_buf);
	if (fd_ctx->qsctx == NULL) {
		errorinfo_createbasic(ei_ctx_ptr, "Failed to decode querystring");
		goto error_rb;
	}
	fd_ctx->buf = read_buf;
	*fd_ctx_ptr = fd_ctx;
	return 0;
error_rb:
	free(read_buf);
error_fd:
	formdecoder_dispose(fd_ctx);
	return -1;
}

/*
 * Take a FCGX_Request (check that it is a POST) and decode the stream.
 * for ease of implementation this will handle both multipart mime style
 * post data and urlencoded data.
 * formdecoder_context will contain the result of the decoding if successful.
 * max_size should set the maximum size in bytes that will be accepted.
 * errorinfo_context should contain some information on what went wrong.
 * Return: 0 on success
 * Return: -1 on failure
 */
int formdecoder_decodefcgirequest(FCGX_Request * req, formdecoder_context ** fd_ctx_ptr, size_t max_size, errorinfo_context ** ei_ctx_ptr) {
	char * request_method;
	char * content_type;
	request_method = FCGX_GetParam("REQUEST_METHOD", req->envp);
	if (request_method == NULL || strcmp("POST", request_method) != 0) {
		errorinfo_createbasic(ei_ctx_ptr, "Request method was not POST");
		return -1;
	}
	content_type = FCGX_GetParam("CONTENT_TYPE", req->envp);
	if (content_type == NULL) {
		errorinfo_createbasic(ei_ctx_ptr, "No content-type header provided");
		return -1;
	}
	if (strncmp("multipart/form-data", content_type, 19) == 0) {
		return formdecoder_decodefcgirequest_multipart(req, fd_ctx_ptr, max_size, ei_ctx_ptr);
	} else
	if (strncmp("application/x-www-form-urlencoded", content_type, 33) == 0) {
		return formdecoder_decodefcgirequest_urlencoded(req, fd_ctx_ptr, max_size, ei_ctx_ptr);
	} else {
		errorinfo_createbasic(ei_ctx_ptr, "Unrecognised content type \"%s\"", content_type);
		fprintf(stderr, "Unrecognised content type \"%s\"\n", content_type);
		return -1;
	}
	return -1;
}


