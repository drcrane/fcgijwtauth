#include "httpclient.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include "dynstring.h"

struct ResponseBuffer {
	unsigned char *data;
	size_t length;
};

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
	struct ResponseBuffer *buf = userdata;
	size_t bytes = size * nmemb;

	if (bytes == 0)
		return 0;

	/* Prevent overflow and enforce the maximum response size. */
	if (bytes > MAX_RESPONSE_SIZE - buf->length)
		return 0;

	size_t new_size = buf->length + bytes;

	unsigned char *new_data = realloc(buf->data, new_size);
	if (new_data == NULL)
		return 0;

	memcpy(new_data + buf->length, ptr, bytes);

	buf->data = new_data;
	buf->length = new_size;

	return bytes;
}

int http_post(const char * url, const char * content_type, const void * post_data, size_t post_length, HttpResponse * response) {
	CURL *curl;
	CURLcode rc;
	char * res_content_type = NULL;
	struct ResponseBuffer buffer = { NULL, 0 };
	struct curl_slist *headers = NULL;

	if (url == NULL || response == NULL)
		return -1;

	memset(response, 0, sizeof(*response));

	curl = curl_easy_init();
	if (curl == NULL)
		return -1;

	curl_easy_setopt(curl, CURLOPT_URL, url);

	dynstring_context_t content_type_dynstr = DYNSTRING_DEFAULT_INIT;
	dynstring_appendstringz(&content_type_dynstr, "Content-Type: ", content_type, NULL);

	headers = curl_slist_append(headers, dynstring_getcstring(&content_type_dynstr));

	if (headers == NULL)
	{
		curl_easy_cleanup(curl);
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)post_length);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20);

	/* Recommended options */
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	//curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

	rc = curl_easy_perform(curl);
	dynstring_free(&content_type_dynstr);

	if (rc != CURLE_OK)
	{
		free(buffer.data);
		curl_easy_cleanup(curl);
		return -1;
	}

	rc = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &res_content_type);
	if (rc == CURLE_OK)
	{
		long http_status = 0;
		rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
		fprintf(stderr, "HTTP STATUS: %d\n", (int)http_status);

		if (res_content_type != NULL && http_status == 200) {
		response->content_type = strdup(res_content_type);
		if (response->content_type == NULL)
		{
			free(buffer.data);
			curl_easy_cleanup(curl);
			return -1;
		}
		}
	}

	response->data = buffer.data;
	response->length = buffer.length;

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	return 0;
}

void http_response_free(HttpResponse *response)
{
	if (response == NULL)
		return;

	free(response->content_type);
	free(response->data);

	response->content_type = NULL;
	response->data = NULL;
	response->length = 0;
}

