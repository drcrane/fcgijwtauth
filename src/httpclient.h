#ifndef HTTP_POST_H
#define HTTP_POST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_RESPONSE_SIZE (1024U * 1024U) /* 1 MiB */

typedef struct
{
	/**
	 * MIME type returned by the server (Content-Type header).
	 * NULL if the server did not provide one.
	 *
	 * This string is allocated by http_post() and must be freed by
	 * calling http_response_free().
	 */
	char *content_type;

	/**
	 * Response body.
	 *
	 * This buffer is allocated by http_post() and may contain arbitrary
	 * binary data. It is not NUL-terminated.
	 */
	void *data;

	/**
	 * Size of the response body in bytes.
	 */
	size_t length;
} HttpResponse;

/**
 * POST binary data to an HTTP server.
 *
 * Parameters:
 *   url		 - URL to POST to.
 *   post_data   - Pointer to data to send.
 *   post_length - Number of bytes to send.
 *   response	- Receives the response.
 *
 * Returns:
 *   0 on success.
 *  -1 on failure.
 *
 * On success, the caller becomes responsible for releasing the response
 * by calling http_response_free().
 */
int http_post(const char * url, const char * content_type, const void * post_data, size_t post_length, HttpResponse * response);

/**
 * Frees all memory owned by an HttpResponse structure.
 *
 * It is safe to call this on a partially initialized or empty response.
 */
void http_response_free(HttpResponse * response);

#ifdef __cplusplus
}
#endif

#endif /* HTTP_POST_H */

