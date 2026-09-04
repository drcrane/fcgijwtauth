#ifndef FORMDECODER_H
#define FORMDECODER_H

#include "mimedecoder.h"
#include "errorinfo.h"
//#include "fcgiapp.h"

#define FORMDECODER_MULTIPART 0
#define FORMDECODER_QUERYSTRING 1
#define FORMDECODER_PRINTFIELDNAMES

#ifdef __cplusplus
#include <memory>

extern "C" {
#endif

struct formdecoder_context;
typedef struct formdecoder_context formdecoder_context;

struct formdecoder_context_field {
	size_t data_len;
	char * data;
	char * mime_type;
	char * filename;
	char * tempfilename;
	int fd;
};

formdecoder_context * formdecoder_init();
void formdecoder_dispose(formdecoder_context * ctx);

/*
 * Set a field with a key.
 * @key  is assumed to be a C nul terminated string and a local copy is created for use by the form decoder.
 * @data is NOT copied, only the pointer is stored by the formdecoder_context.
 *       if data is not null it will be freed when the formdecoder_context is destroyed.
 */
int formdecoder_setfield(formdecoder_context * ctx, char * key, size_t data_len, char * data);

/*
 * Get the value from a field with the name key
 * @key          nul terminated C string
 * @data_len_ptr length of data returned in data_ptr
 * @data_ptr     data present in the form field
 * return 0 on success
 */
int formdecoder_getfield(formdecoder_context * ctx, const char * key, size_t * data_len_ptr, char ** data_ptr);

/*
 * Get the pointer to the internal field representation
 * important for when the field is a file.
 */
struct formdecoder_context_field * formdecoder_getfieldex(formdecoder_context * ctx, const char * key, size_t idx);

/*
 * Callback to generate the stuff for the stuff.
 */
int formdecoder_mimedecoder_callback(mimedecoder_context * ctx, int event, void * ptr, size_t ptr_size);

/*
 * Find the field and remove it from the array.
 */
int formdecoder_takefieldvalue(formdecoder_context * ctx, char * key, size_t * data_len, char ** data);

/*
 * Count of the fields in the context
 */
size_t formdecoder_fieldcount(formdecoder_context * ctx);

#ifdef __cplusplus
}

struct formdecoder_deleter {
	void operator()(formdecoder_context* ctx) const noexcept {
		if (ctx) {
			formdecoder_dispose(ctx);
		}
	}
};

using formdecoder_context_ptr =
    std::unique_ptr<formdecoder_context, formdecoder_deleter>;

/*
 * Use like this:
formdecoder_context_ptr decode_request() {
	formdecoder_context* ctx = nullptr;
	formdecoder_decodefcgirequest(req, &ctx, 1024 * 1024, nullptr);
	return formdecoder_context_ptr(ctx);
}
*/
#endif

#endif /* FORMDECODER_H */

