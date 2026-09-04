#ifndef FORMDECODER_FASTCGI_H
#define FORMDECODER_FASTCGI_H

#include "formdecoder.h"
#include "errorinfo.h"
#include <fcgiapp.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decode the form from a fast cgi request object
 * this works with multipart mime forms and urlencoded forms
 *
 * @arg req the request containing the data that is to be decoded
 * @arg ctx_ptr pointer to where new form decoder will be created
 * @arg max_size maximum size in bytes that should be decoded
 * @arg ei_ctx set this to NULL
 */
int formdecoder_decodefcgirequest(FCGX_Request * req, formdecoder_context ** ctx_ptr, size_t max_size, errorinfo_context ** ei_ctx);
void formdecoder_dump_envp(FCGX_Request * request);

#ifdef __cplusplus
}
#endif

#endif // FORMDECODER_FASTCGI_H
