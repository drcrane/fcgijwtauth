#define _POSIX_C_SOURCE 200809

#include <string.h>
#include <unistd.h> // close, write, mkstemp
#include <malloc.h>
#include <stddef.h>
//#include <fcgiapp.h>
#include "dbg.h"
#include "formdecoder.h"
#include "dynstring.h"
#include "contentdisposition.h"
//#include "errorinfo.h"
#include "querystring.h"
#include "simplemap.h"

struct formdecoder_context {
	int type;

	simplemap_context * fields;
	struct formdecoder_context_field * current_field;

	dynstring_context_t current_field_data;
	char * buf;
	querystring_context * qsctx;
	int save_files;
};

static char * formdecoder_strdup(char * str) {
	size_t len = strlen(str);
	len ++;
	char * new_str = malloc(len);
	memcpy(new_str, str, len);
	return new_str;
}

formdecoder_context * formdecoder_init() {
	formdecoder_context * ctx;
	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) { return NULL; }
	dynstring_initialisezero(&ctx->current_field_data);
	ctx->fields = simplemap_create(10);
	ctx->buf = NULL;
	ctx->type = FORMDECODER_MULTIPART;
	ctx->qsctx = NULL;
	ctx->save_files = 0;
	ctx->current_field = NULL;
	return ctx;
}

/*
 * Values returned are null terminated by implementation.
 * Be careful if altered!
 */
int formdecoder_takefieldvalue(formdecoder_context * ctx, char * key, size_t * data_len, char ** data) {
	int res = -1;
	size_t key_len;
	struct formdecoder_context_field * removed;
	size_t removed_sz;
	key_len = strlen(key);
	res = simplemap_removebykey(ctx->fields, key, key_len, 0, (void **)&removed, &removed_sz);
	if (res == 0) {
		*data_len = removed->data_len;
		*data = removed->data;
		free(removed);
	}
	return res;
}

static void formdecoder_dispose_formfield(struct formdecoder_context_field * field) {
	if (field->data) {
		free(field->data);
	}
	if (field->mime_type) {
		free(field->mime_type);
	}
	if (field->filename) {
		free(field->filename);
	}
	if (field->fd != -1) {
		close(field->fd);
		field->fd = -1;
	}
	if (field->tempfilename) {
		debug("disposing tempfilename %s", field->tempfilename);
		unlink(field->tempfilename);
		free(field->tempfilename);
	}
	free(field);
}

void formdecoder_dispose(formdecoder_context * ctx) {
	if (ctx->buf) {
		free(ctx->buf);
	}
	if (ctx->qsctx) {
		querystring_dispose(ctx->qsctx);
	}
	dynstring_free(&ctx->current_field_data);
	simplemap_dispose_cb(ctx->fields, (simplemap_datacallback)formdecoder_dispose_formfield);
	free(ctx);
}

int formdecoder_setfield(formdecoder_context * ctx, char * key, size_t data_len, char * data) {
	size_t key_len;
	size_t field_len;
	struct formdecoder_context_field * replaced;
	struct formdecoder_context_field * field;
	struct formdecoder_context_field * to_insert;
	int res;
	key_len = strlen(key);
	res = simplemap_findfromkey(ctx->fields, key, key_len, 0, (void **)&field, &field_len);
	if (res == 0) {
		return -1;
	}
	to_insert = malloc(sizeof(struct formdecoder_context_field));
	if (to_insert == NULL) { return -1; }
	memset(to_insert, 0, sizeof(struct formdecoder_context_field));
	to_insert->data = data;
	to_insert->data_len = data_len;
	replaced = NULL;
	res = simplemap_addorreplace(ctx->fields, key, key_len, 0, (void **)&replaced, to_insert, sizeof(struct formdecoder_context_field));
	if (replaced) {
		formdecoder_dispose_formfield(replaced);
	}
	return res;
}

/*
 * Get a field from the formdecoder_context:
 * return values:
 * - 0: Key found: data_ptr and data_ptr_len updated to point to the field (not copied, do not modify the data)
 * - non-zero: Key not found data_ptr and data_ptr_len not modified
 */
int formdecoder_getfield(formdecoder_context * ctx, const char * key, size_t * data_len_ptr, char ** data_ptr) {
	if (ctx->type == FORMDECODER_QUERYSTRING) {
		char * field_value;
		field_value = querystring_getbykey(ctx->qsctx, key);
		if (field_value) {
			if (data_len_ptr != NULL) {
				*data_len_ptr = strlen(field_value);
			}
			*data_ptr = field_value;
			return 0;
		}
	} else
	if (ctx->type == FORMDECODER_MULTIPART) {
		struct formdecoder_context_field * field;
		int res;
		size_t key_len;
		size_t field_len;
		key_len = strlen(key);
		res = simplemap_findfromkey(ctx->fields, key, key_len, 0, (void **)&field, &field_len);
		*data_ptr = field->data;
		*data_len_ptr = field->data_len;
		return res;
	}
	return -1;
}

struct formdecoder_context_field * formdecoder_getfieldex(formdecoder_context * ctx, char * key, size_t idx) {
	if (ctx->type == FORMDECODER_MULTIPART) {
		size_t key_len;
		struct formdecoder_context_field * field = NULL;
		size_t field_len;
		key_len = strlen(key);
		simplemap_findfromkey(ctx->fields, key, key_len, idx, (void **)&field, &field_len);
		return field;
	}
	return NULL;
}

size_t formdecoder_fieldcount(formdecoder_context * ctx) {
	return simplemap_count(ctx->fields);
}

int formdecoder_mimedecoder_callback(mimedecoder_context * ctx, int event, void * ptr, size_t ptr_size) {
	formdecoder_context * fd_ctx;
	fd_ctx = (formdecoder_context *)ctx->user_context;
	//debug("formdecoder_mimedecoder_callback(%d)", event);
	switch (event) {
	case MIMED_EVENT_HEADER:
		//debug("formdecoder MIMEDECODER_EVENT_HEADER");
		if (strncmp(ctx->current_header.header_name.buf, "Content-Disposition", ctx->current_header.header_name.pos) == 0) {
			if (strncmp(ctx->current_header.header_value.buf, "form-data", 9) == 0) {
				char * name = NULL;
				char * filename = NULL;
				name = contentdisposition_getname(ctx->current_header.header_value.buf);
				if (name) {
					if (fd_ctx->current_field != NULL) {
						debug("current_field not null, could this be a duplicate Content-Disposition header?");
						free(name);
						return -1;
						//fd_ctx->current_field->filename
					} else {
						fd_ctx->current_field = malloc(sizeof(struct formdecoder_context_field));
						if (fd_ctx->current_field == NULL) {
							debug("fd_ctx->current_field is NULL");
							free(name);
							return -1;
						}
						memset(fd_ctx->current_field, 0, sizeof(struct formdecoder_context_field));
						fd_ctx->current_field->fd = -1;
						simplemap_append(fd_ctx->fields, name, strlen(name), fd_ctx->current_field, sizeof(struct formdecoder_context_field));
#ifdef FORMDECODER_PRINTFIELDNAMES
						debug("formdecoder FIELD NAME %s", name);
#endif /* FORMDECODER_PRINTFIELDNAMES */
					}
					free(name);
				}
				filename = contentdisposition_getfilename(ctx->current_header.header_value.buf);
				if (fd_ctx->current_field && filename && fd_ctx->save_files) {
					int fd;
					char * tempfilename = formdecoder_strdup("/tmp/formdecoder.XXXXXX");
					debug("formdecoder FILE DETECTED %s", filename);
					//free(filename);
					fd_ctx->current_field->filename = filename;
					fd = mkstemp(tempfilename);
					if (fd == -1) {
						debug("Error creating temp file!");
						free(tempfilename);
						return -1;
					}
					fd_ctx->current_field->tempfilename = tempfilename;
					fd_ctx->current_field->fd = fd;
					debug("formdecoder CREATE FILE %s", tempfilename);
				}
			}
		} else
		if (strncmp(ctx->current_header.header_name.buf, "Content-Type", ctx->current_header.header_name.pos) == 0) {
			// Relies on the header_value being nul terminated
			fd_ctx->current_field->mime_type = formdecoder_strdup(ctx->current_header.header_value.buf);
			debug("Content-Type: %s", fd_ctx->current_field->mime_type);
		}
		break;
//	case MIMED_EVENT_ELEMENT_END:
//		break;
	case MIMED_EVENT_ELEMENT_BEGIN:
		if (fd_ctx->current_field == NULL) {
			return -1;
		}
		if (fd_ctx->current_field_data.buf != NULL) {
			debug("current_field_data is not NULL");
			return -1;
		}
		if (fd_ctx->current_field->fd == -1) {
			dynstring_initialise(&fd_ctx->current_field_data, 64);
		}
		break;
	case MIMED_EVENT_ELEMENT_CHUNK:
	{
		struct formdecoder_context_field * current_field;
		ssize_t rc;
		current_field = fd_ctx->current_field;
		if (current_field == NULL) {
			return -1;
		}
		current_field->data_len += ptr_size;
		if (current_field->fd == -1) {
			dynstring_appendstring(&fd_ctx->current_field_data, (char *)ptr, ptr_size);
		} else {
			rc = write(current_field->fd, ptr, ptr_size);
			if (rc != ptr_size) {
				debug("rc != ptr_size in EVENT_BODY_CONTENT (fd %d)", current_field->fd);
				return -1;
			}
		}
		//debug("MIMEDECODER_EVENT_BODY_CONTENT appended %d bytes", (int)ptr_size);
	}
		break;
	case MIMED_EVENT_ELEMENT_END:
		if (fd_ctx->current_field == NULL) {
			debug("NULL!");
		} else {
			if (fd_ctx->current_field->fd == -1) {
				fd_ctx->current_field->data_len = dynstring_length(&fd_ctx->current_field_data);
				// detaching the string moves responsibility for this memory away from the dynstring
				fd_ctx->current_field->data = dynstring_detachcstring(&fd_ctx->current_field_data);
			} else {
				close(fd_ctx->current_field->fd);
				fd_ctx->current_field->fd = -1;
			}
			fd_ctx->current_field = NULL;
		}
		break;
	default:
		debug("executed default for some reason");
		return -1;
	}
	return 0;
}

