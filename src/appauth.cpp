#include <fcgiapp.h>
#include <stdio.h>
#include <cstdlib>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <map>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <vector>
#include <sstream>
#include <iomanip>
#include <mutex>
#include "../src/HTTPUtils.hpp"
#include "jwt-cpp/jwt.h"
#include "jwt-cpp/traits/kazuho-picojson/traits.h"
#include "../src/JWKSVerifierStore.hpp"
#include "application.hpp"
#include "querystring.h"
#include "dynstring.h"
#include "dynstringhtml.h"
#include "formdecoder.h"
#include "formdecoder_fastcgi.h"
#include "timefn.h"
#include "appspecific.h"
#include "openidconnect.h"
#include "httpclient.h"
#include "simpletemplate.hpp"
#include "strutils.h"

//#define OPTION_NOREDIRECTS

using json_traits = jwt::traits::kazuho_picojson;

JWKSStoreManager g_store_man{};

struct TimedJWTEntry {
    std::string value;
    std::chrono::steady_clock::time_point expires_at;
};
std::unordered_map<std::string, TimedJWTEntry> g_codes_to_jwts{};
void g_codes_to_jwts_remove_expired() {
	auto & cache = g_codes_to_jwts;
	auto now = std::chrono::steady_clock::now();
	for (auto it = cache.begin(); it != cache.end(); ) {
		if (now >= it->second.expires_at) {
			fprintf(stderr, "Removing expired token\n");
			it = cache.erase(it);
		} else {
			++it;
		}
	}
}

int get_tokens_from_microsoft(const char * code, char ** json, char ** token_ptr) {
	HttpResponse response = { .content_type = NULL, .data = NULL, .length = 0 };
	int res;
	dynstring_context_t post_data = DYNSTRING_DEFAULT_INIT;
	fprintf(stderr, "Checking if we already have a token...\n");
	if (auto existing_tok = g_codes_to_jwts.find(code); existing_tok != g_codes_to_jwts.end()) {
		using namespace std::chrono_literals;
		fprintf(stderr, "Existing token found %s\n", existing_tok->second.value.c_str());
		existing_tok->second.expires_at = std::chrono::steady_clock::now() + 30s;
		*token_ptr = strdup(existing_tok->second.value.c_str());
		return 0;
	}
	g_codes_to_jwts_remove_expired();
	fprintf(stderr, "Getting tokens from Microsoft\n");
	dynstring_appendstringz(&post_data, "client_id=" OAUTH2_DEFAULT_CLIENT_ID "&", NULL);
	dynstring_appendstringz(&post_data, "client_secret=" OAUTH2_DEFAULT_CLIENT_SECRET "&", NULL);
	dynstring_appendstringz(&post_data, "scope=openid%20profile%20email&", NULL);
	dynstring_appendstringz(&post_data, "code=", NULL);
	dynstringhtml_url_encode_appendz(&post_data, code);
	dynstring_appendstringz(&post_data, "&", NULL);
	dynstring_appendstringz(&post_data, "redirect_uri=" OAUTH2_DEFAULT_REDIRECT_URI "&", NULL);
	dynstring_appendstringz(&post_data, "grant_type=authorization_code", NULL);
	fprintf(stderr, "%s\n", dynstring_getcstring(&post_data));
	res = http_post("https://login.microsoftonline.com/common/oauth2/v2.0/token", "application/x-www-form-urlencoded", dynstring_getcstring(&post_data), dynstring_length(&post_data), &response);
	//fprintf(stderr, "res = %d\n", res);
	int rc = -2;
	if (res == 0) {
		//fprintf(stderr, "%.*s\n", (int)response.length, (const char *)response.data);
		//std::string_view inputjson = std::string_view((const char *)response.data, response.length);
		std::string inputjson = std::string((const char *)response.data, response.length);
		try {
			json_traits::value_type val;
			json_traits::parse(val, inputjson);
			if (((picojson::value &)val).is<picojson::object>()) {
				const picojson::object & obj = ((picojson::value &)val).get<picojson::object>();
				const picojson::value & token_json_value = obj.find("id_token")->second;
				if (token_json_value.is<std::string>()) {
					using namespace std::chrono_literals;
					std::string token = token_json_value.get<std::string>();
					//fprintf(stderr, "> %s\n", token.c_str());
					*token_ptr = strdup(token.c_str());
					TimedJWTEntry timed_token{};
					timed_token.value = token;
					timed_token.expires_at = std::chrono::steady_clock::now() + 30s;
					auto [it, inserted] = g_codes_to_jwts.try_emplace(std::string{code}, timed_token);
					if (inserted) {
						fprintf(stderr, "Added the code and token...\n");
					}
					rc = 0;
				}
			}
		} catch (std::exception & e) {
			fprintf(stderr, "Exception when trying to get the token:\n%s\n", e.what());
			rc = -1;
		}
	} else {
		rc = -1;
	}
	http_response_free(&response);
	dynstring_free(&post_data);
	*json = NULL;
	return rc;
}

/*
 * Parse the post request to find the username, compose a forwarding url and
 * redirect the user.
 */
int process_login_page_post(FCGX_Request * req, HTTPUtils::RequestContext & req_ctx) {
	querystring_context * qs_ctx = req_ctx.qs;
	int res;
	formdecoder_context * fd_ctx = NULL;
	res = formdecoder_decodefcgirequest(req, &fd_ctx, 1024*1024, NULL);
	if (res != 0) {
		debug("Failed to decode input");
		return 0;
	}
	if (fd_ctx == NULL) {
		debug("fd_ctx == NULL");
		return 0;
	}
	// Check for valid input and then try and forward to the provider
	// (at this point we don't care too much about the email address provided
	// by the user)
	size_t provider_len = 0;
	char * provider = NULL;
	res = formdecoder_getfield(fd_ctx, "provider", &provider_len, &provider);
	//fprintf(stderr, "%d provider = %.*s\n", res, (int)provider_len, provider);
	if (res == 0 && provider_len == sizeof("microsoft") - 1 && provider != NULL && memcmp("microsoft", provider, sizeof("microsoft") - 1) == 0) {
		char * verifyable_string = NULL;
		int64_t current_unix_time = timefn_getcurrentunixtime();
		std::string current_time = timefn_formattimefromunixtime_str(current_unix_time);
		std::string send_to = "/";
		size_t redirect_to_len = 0;
		char * redirect_to = NULL;
		res = formdecoder_getfield(fd_ctx, "redirect_to", &redirect_to_len, &redirect_to);
		if (res == 0 && redirect_to_len > 4 && redirect_to != NULL) {
			send_to = std::string(redirect_to, redirect_to_len);
			debug("redirect found = %s", send_to.c_str());
		}
		debug("send_to = %s", send_to.c_str());
		openidconnect_create_verifyable_string(OAUTH2_DEFAULT_CLIENT_SECRET, (send_to + '.' + current_time).c_str(), &verifyable_string);
		debug("found provider microsoft, composing redirect");
		debug("verifyable_string %s", verifyable_string);
		dynstring_context_t redirect_uri = DYNSTRING_DEFAULT_INIT;
		dynstring_appendstringz(&redirect_uri, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"
				"client_id=" OAUTH2_DEFAULT_CLIENT_ID "&"
				"response_type=code&"
				"scope=openid%20profile%20email&"
				"redirect_uri=" OAUTH2_DEFAULT_REDIRECT_URI "&"
				"state=",
				NULL);
		dynstringhtml_url_encode_appendz(&redirect_uri, verifyable_string);
		free(verifyable_string);
		dynstring_appendstringz(&redirect_uri,
				"&prompt=select_account",
				NULL);
		dynstring_context_t page = DYNSTRING_DEFAULT_INIT;
		dynstring_appendstringz(&page,
#ifdef OPTION_NOREDIRECTS
				"Status: 200\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
#endif
#ifndef OPTION_NOREDIRECTS
				"Status: 302\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"Location: ", dynstring_getcstring(&redirect_uri), "\r\n"
#endif
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html>\r\n"
				"<head></head>\r\n"
				"<body>\r\n"
				"<p><a href=\"", dynstring_getcstring(&redirect_uri), "\">Authenticate at Microsoft</a></p>\r\n"
				"<p>", dynstring_getcstring(&redirect_uri), "</p>\r\n"
				"</body>\r\n"
				"</html>\r\n",
				NULL);
		//std::string & login_page = application_login_page_get_content();
		//dynstring_appendstringz(&page, "Status: 200\r\n"
		//		"Content-Type: text/html; charset=utf-8\r\n"
		//		"\r\n",
		//		login_page.c_str(),
		//		NULL);
		FCGX_PutStr(dynstring_getcstring(&page), dynstring_length(&page), req->out);
		/*
		dynstring_appendstringz(&page, "Status: 302\r\n"
				"Content-Type: text/html\r\n"
				"Location: ", dynstring_getcstring(&redirect_uri), "\r\n"
				"\r\n"
				, NULL);
		*/
		dynstring_free(&redirect_uri);
		dynstring_free(&page);
	} else {
		FCGX_PutS(
				"Status: 400 Bad Request\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html><head></head><body>\r\n"
				"<h1>400 Bad Request</h1>\r\n"
				"<p>Well, I don't know what that was supposed to be but I cannot process it.</p>\r\n"
				"</body></html>\r\n",
				req->out);
	}
	formdecoder_dispose(fd_ctx);
	FCGX_Finish_r(req);
	fprintf(stderr, "POST Finished\n");
	return 0;
}

char * truncate_at_second_last_dot(char * str) {
	if (str == NULL)
		return NULL;

	char * p = str + strlen(str);
	char * last_dot = NULL;
	char * second_last_dot = NULL;

	while (p != str) {
		--p;

		if (*p == '.') {
			if (last_dot == NULL) {
				last_dot = p;
			} else {
				second_last_dot = p;
				break;
			}
		}
	}

	if (second_last_dot == NULL)
		return NULL;

	*second_last_dot = '\0';
	return second_last_dot + 1;
}

int process_code_response(FCGX_Request * req, HTTPUtils::RequestContext & req_ctx) {
	querystring_context * qs_ctx = req_ctx.qs;
	char const * qs_code = querystring_getbykey(qs_ctx, "code");
	char const * qs_state = querystring_getbykey(qs_ctx, "state");
	char const * qs_error = querystring_getbykey(qs_ctx, "error");
	char const * qs_error_description = querystring_getbykey(qs_ctx, "error_description");
	//char * cookie = FCGX_GetParam("HTTP_COOKIE", req->envp);
	//fprintf(stderr, "Cookie: %s\n", cookie);
	//cookie_t * cookies = HTTPUtils_parse_cookies(cookie);
	//char const * jwtoken_ptr = HTTPUtils_get_cookie(cookies, "auth", 0);
	char const * jwtoken_ptr = HTTPUtils_get_cookie(req_ctx.cookies, "auth", 0);
	std::string jwtoken_ptr_str = jwtoken_ptr ? jwtoken_ptr : "";
	DynStringGuard jwt_content{};
	int res;
	fprintf(stderr, "process_code_response() ---- ---- ----\n");
	if (jwtoken_ptr_str == "") {
		dynstring_appendstringz(jwt_content.ptr(), "NO CONTENT: ERROR\r\n", NULL);
	} else {
		std::unique_ptr<JWTUserContext> user_ctx = jwtinterface_getusercontext(jwtoken_ptr_str);
		if (user_ctx) {
			fprintf(stderr, "USER: %s\n", user_ctx->email_address.c_str());
			dynstring_appendstringz(jwt_content.ptr(), user_ctx->header_json_str.c_str(), "\r\n", NULL);
			dynstring_appendstringz(jwt_content.ptr(), user_ctx->payload_json_str_pretty.c_str(), "\r\n", NULL);
		}
	}

	char * json = NULL;
	char * jwtoken = NULL;
	const char * redirect_url = NULL;
	std::string jwtoken_str;
	dynstring_context_t page = DYNSTRING_DEFAULT_INIT;
	if (qs_error != NULL) {
		dynstring_appendstringz(&page,
				"Status: 200\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html><head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"<style>\r\n"
				"*, body { font-family: sans-serif; }\r\n"
				"</style>\r\n"
				"</head>\r\n"
				"<body>\r\n"
				"<h1>Error Returned by Microsoft</h1>\r\n"
				"<p>Error Code: <code>", qs_error, "</code></p>\r\n",
				NULL);
		if (qs_error_description) {
			dynstring_appendstringz(&page,
					"<h2>Further Detail of this Error</h2>"
					"<p>", NULL);
			dynstringhtml_htmlspecial_encode_appendz(&page,
					qs_error_description);
			dynstring_appendstringz(&page, "</p>\r\n", NULL);
		}
		dynstring_appendstringz(&page,
				"<p><a href=\"/\">Click here to try again.</a></p>\r\n"
				"</body>\r\n"
				"</html>\r\n",
				NULL);
		goto finished;
	}
	if (qs_code == NULL || qs_state == NULL) {
		dynstring_appendstringz(&page,
				"Status: 400\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html><head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"</head><body>\r\n"
				"<h1>400 Bad Request</h1>\r\n"
				"<p>Seems that no <code>code</code> or <code>state</code> argument were supplied.</p>\r\n",
				NULL);
		if (jwtoken_ptr_str != "") {
			dynstring_appendstringz(&page, "<p>Generally this is not a page that the developer expects you to see, sorry for that. Since you have a token you should go <a href=\"/\">back home</a> and, if possible, please report this to the developer.</p>\r\n", NULL);
		}
		dynstring_appendstringz(&page,
				"<pre>",
				NULL);
		dynstringhtml_htmlspecial_encode_appendz(&page, dynstring_getcstring(jwt_content.ptr()));
		dynstring_appendstringz(&page,
				"</pre>\r\n"
				"</body></html>\r\n",
				NULL);
		goto finished;
	}
	res = openidconnect_verify_string(OAUTH2_DEFAULT_CLIENT_SECRET, qs_state);
	fprintf(stderr, "qs_code %s\n", qs_code);
	fprintf(stderr, "qs_state %s\n", qs_state);
	fprintf(stderr, "verify_string() %d\n", res);
	if (res != 0) {
		dynstring_appendstringz(&page,
				"Status: 400\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html><head></head><body>\r\n"
				"<h1>400 Error</h1>\r\n"
				"<p>Seems that the verifyable string was not verifyable, sorry.</p>\r\n"
				"</body></html>\r\n",
				NULL);
		goto finished;
	}
	redirect_url = truncate_at_second_last_dot((char *)qs_state);
	if (redirect_url == NULL) {
//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wwrite-strings"
		redirect_url = "";
//#pragma GCC diagnostic pop
	} else {
		redirect_url = qs_state;
	}
	res = get_tokens_from_microsoft(qs_code, &json, &jwtoken);
	if (res != 0) {
		dynstring_appendstringz(&page,
				"Status: 500\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html><head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"</head><body>\r\n"
				"<h1>500 Error</h1>\r\n"
				"<p>Token retrieval failed.</p>\r\n"
				"</body></html>\r\n",
				NULL);
		goto finished;
	}
	free(json);
	if (jwtoken == NULL) {
		dynstring_appendstringz(&page,
				"Status: 500\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html><head></head><body>\r\n"
				"<h1>500 Error</h1>\r\n"
				"<p>Token was null.</p>\r\n"
				"</body></html>\r\n",
				NULL);
		goto finished;
	}
	jwtoken_str = std::string{ jwtoken };
	res = verify_jwks_authentication_jwt(g_store_man, jwtoken_str);
	fprintf(stderr, "verify_jwks_authentication_jwt() %s (%d)\n", res == 0 ? "VERIFIED" : "NOT VERIFIED", res);
	if (res != 0) {
		dynstring_appendstringz(&page,
				"Status: 401\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html><head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"</head><body>\r\n"
				"<h1>401 Unauthorized</h1>\r\n"
				"<p>verify_jwks_authentication_jwt() failed.</p>\r\n"
				"</body></html>\r\n",
				NULL);
		goto finished;
	}
	dynstring_appendstringz(&page,
#ifdef OPTION_NOREDIRECTS
			"Status: 200\r\n"
			//"Set-Cookie: auth=", jwtoken, "; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
#endif
#ifndef OPTION_NOREDIRECTS
			"Status: 302\r\n"
			"Set-Cookie: auth=", jwtoken, "; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"Location: ", redirect_url, "\r\n"
#endif
			"\r\n"
			"<!DOCTYPE html>\r\n"
			"<html>\r\n"
			"<head>\r\n"
			"<meta charset=\"UTF-8\" />\r\n"
			"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
			"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
			"</head>\r\n"
			"<body>\r\n"
			"<h1>Authenticated</h1>\r\n"
			/*"<pre>",
			jwtoken,
			"</pre>\r\n"*/
			"<p>If you are not redirected automatically please "
			"<a href=\"",
			redirect_url,
			"\">click here (",
			redirect_url,
			")</a>.</p>\r\n"
			"<p>", "Token Details Here", "</p>\r\n"
			"<p><a href=\"direct?token=",
			jwtoken,
			"&state=",
			qs_state,
			"\">Click here</a> to set the token as the <code>auth</code> cookie and continue...</p>\r\n"
			"</body>\r\n"
			"</html>\r\n",
			NULL);
	free(jwtoken);
finished:
	FCGX_PutStr(dynstring_getcstring(&page), dynstring_length(&page), req->out);
	dynstring_free(&page);
	FCGX_FFlush(req->out);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

/*
 * parse_first_number - parse a path component of a '/'-delimited path as an int.
 *
 * Rules:
 *   - The path MUST begin with '/' (otherwise 0 is returned).
 *   - delimiter_count is a 1-based index of a path component: the component
 *     parsed is the text immediately following the delimiter_count-th '/',
 *     up to the next '/' or the terminating '\0'.
 *       "/a/8472/b":  count 1 -> "a",  count 2 -> "8472",  count 3 -> "b"
 *   - The selected component must consist ENTIRELY of decimal digits.
 *     Any other character (letter, '-', '.', or an empty component) fails.
 *   - The number must end with '/' or '\0' - guaranteed by component
 *     boundaries, but enforced by rejecting partial digit runs.
 *   - On any failure (NULL input, bad prefix, invalid/missing delimiter,
 *     non-digits, overflow) the function returns 0.
 */
int appauth_parse_first_number(int delimiter_count, char const * str) {
	if (str == NULL || delimiter_count <= 0) {
		return 0;
	}

	if (str[0] != '/') {
		return 0;
	}

	/* Advance past the delimiter_count-th '/' in the string. */
	char const * p = str;
	for (int i = 0; i < delimiter_count; i++) {
		while (*p != '\0' && *p != '/') {
			p++;
		}
		if (*p == '\0') {
			return 0;
		}
		p++;
	}

	/* The component must be all digits, terminated by '/' or '\0'. */
	const char *start = p;
	while (isdigit((unsigned char)*p)) {
		p++;
	}
	if (p == start) {
		return 0;
	}
	if (*p != '/' && *p != '\0') {
		return 0;
	}

	/* Parse the digit run, rejecting values that do not fit in an int. */
	errno = 0;
	char *endp = NULL;
	long value = strtol(start, &endp, 10);

	if (errno != 0 || endp != p || value < 0 || value > INT_MAX) {
		return 0;
	}

	return (int)value;
}

int process_verification_request(FCGX_Request * req, HTTPUtils::RequestContext & req_ctx) {
	querystring_context * qs_ctx = req_ctx.qs;
	// Look for an Authorization header or Cookie
	//char * authorisation = FCGX_GetParam("HTTP_AUTHORIZATION", req->envp);
	//char * request_uri = FCGX_GetParam("REQUEST_URI", req->envp);
	int res = 0;
	//fprintf(stderr, "Authorization: %s\n", authorisation);
	fprintf(stderr, "Request URI: %s\n", req_ctx.request_uri.c_str());
	std::unique_ptr<JWTUserContext> user_ctx;
	if ((user_ctx = application_verify_jwt_authentication(&g_store_man, req_ctx.cookies))) {
#ifdef APPLICATION_AUTHORISATION_VERIFICATION
		if (appspecific_authorisation_verification(req, req_ctx, *user_ctx) == 0) {
			// validation success
		} else {
			// 403...
			goto authorisation_failed;
		}
#endif // APPLICATION_AUTHORISATION_VERIFICATION
		FCGX_FPrintF(req->out, "Status: 200\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html>\r\n"
				"<head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"<title>Authorisation</title>\r\n"
				"</head>\r\n"
				"<body>\r\n"
				"<h1>200 Authorisation (%d)</h1>\r\n"
				"</body>\r\n"
				"</html>\r\n", res);
	} else {
		goto unauthorized;
unauthorized:
		fprintf(stderr, "401 Unauthorized\n");
		FCGX_FPrintF(req->out, "Status: 401 Unauthorized\r\n"
		//FCGX_FPrintF(req->out, "Status: 403 Forbidden\r\n"
				//"WWW-Authenticate: Bearer realm=\"private_files\" scope=\"openid profile email\"\r\n"
				// error= error_description= and error_uri= are available for more detail
				// see RFC 6750 section 3
				// error="invalid_token" for 401 response
				// error="insufficient_scope" for 403 response (the header may not be relayed by nginx)
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html>\r\n"
				"<head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"<title>401 Unauthorized</title>\r\n"
				"</head>\r\n"
				"<body>\r\n"
				"<h1>401 Unauthorized (%d)</h1>\r\n"
				"</body>\r\n"
				"</html>\r\n", res);
		goto finished;
authorisation_failed:
		fprintf(stderr, "403 Forbidden\n");
		FCGX_FPrintF(req->out, "Status: 403 Forbidden\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html>\r\n"
				"<head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"<title>403 Forbidden</title>\r\n"
				"</head>\r\n"
				"<body>\r\n"
				"<h1>401 Forbidden (%d)</h1>\r\n"
				"</body>\r\n"
				"</html>\r\n", res);
		goto finished;
	}
finished:
	FCGX_FFlush(req->out);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

int process_login_page_get(FCGX_Request * req, char * query_string) {
	// IMPORTANT: This page is special since we need to treat the 'return' argument properly if it should contain stuff like & = or other URL escaping complications
	dynstring_context_t page = DYNSTRING_DEFAULT_INIT;
	char * authorisation = FCGX_GetParam("HTTP_AUTHORIZATION", req->envp);
	char * cookie = FCGX_GetParam("HTTP_COOKIE", req->envp);
	int res;
	fprintf(stderr, "Authorization: %s\n", authorisation);
	fprintf(stderr, "Cookie: %s\n", cookie);
	const char * return_to = NULL;
	if (query_string != NULL && strlen(query_string) >= 8) {
		if (strncmp(query_string, "return=", 7) == 0 && query_string[7] == '/' && query_string[8] != '/') {
			return_to = query_string + 7;
		}
	}
	if (return_to == NULL) {
		return_to = "/";
	}
	// If we are already authenticated and the token is valid then just follow the
	// return argument immediately.
	if ((cookie != NULL || authorisation != NULL) && (res = verify_jwks_authentication(g_store_man, cookie, authorisation)) == 0) {
		FCGX_FPrintF(req->out,
				"Status: 302\r\n"
				"Location: %s\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html>\r\n"
				"<head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"<title>Authorisation</title>\r\n"
				"</head>\r\n"
				"<body>\r\n"
				"<h1>200 Authorisation (%d)</h1>\r\n"
				"</body>\r\n"
				"</html>\r\n", return_to, res);
	}

	std::string login_page = application_login_page_get_content();
	TemplateEngine templ = TemplateEngine(login_page);
	templ.SetVariable("REDIRECT_URL", std::string(return_to));
	std::string final_page = templ.Render();
	dynstring_appendstringz(&page, "Status: 200\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"\r\n",
			final_page.c_str(),
			NULL);
finished:
	FCGX_PutStr(dynstring_getcstring(&page), dynstring_length(&page), req->out);
	dynstring_free(&page);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

int process_direct_token_auth_request(FCGX_Request * req, HTTPUtils::RequestContext & req_ctx) {
	querystring_context * qs = req_ctx.qs;
	dynstring_context_t page = DYNSTRING_DEFAULT_INIT;
	char const * jwtoken;
	std::string jwtoken_str;
	int res = 0;
	jwtoken = querystring_getbykey(req_ctx.qs, "token");
	if (jwtoken == NULL) {
		FCGX_FPrintF(req->out, "Status: 401 Unauthorized\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html>\r\n"
				"<head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"<title>401 Unauthorized</title>\r\n"
				"</head>\r\n"
				"<body>\r\n"
				"<h1>400 Bad Request</h1>\r\n"
				"<p><code>token</code> MUST be supplied.</p>\r\n"
				"</body>\r\n"
				"</html>\r\n");
		goto finished;
	}
	jwtoken_str = std::string{ jwtoken };
	res = verify_jwks_authentication_jwt(g_store_man, jwtoken_str);
	fprintf(stderr, "verify_jwks_authentication_jwt() %s (%d)\n", res == 0 ? "VERIFIED" : "NOT VERIFIED", res);
	if (res != 0) {
		FCGX_FPrintF(req->out, "Status: 401\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html>\r\n"
				"<head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"<title>401 Unauthorized</title>\r\n"
				"</head>\r\n"
				"<body>\r\n"
				"<h1>401 Unauthorized</h1>\r\n"
				"<p>Could not verify supplied token, rc = %d.</p>\r\n"
				"</body>\r\n"
				"</html>\r\n", res);
		goto finished;
	}
	{
		char const * qs_state = querystring_getbykey(req_ctx.qs, "state");
		if (qs_state == NULL) {
			qs_state = "(null?)";
		}
		FCGX_FPrintF(req->out, "Status: 200\r\n"
				"Set-Cookie: auth=%s; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html>\r\n"
				"<head>\r\n"
				"<meta charset=\"UTF-8\" />\r\n"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
				"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
				"<title>200 OK</title>\r\n"
				"</head>\r\n"
				"<body>\r\n"
				"<h1>200 OK</h1>\r\n"
				"<p>Supplied token verified and accepted.</p>\r\n"
				"<p>%s</p>\r\n"
				"</body>\r\n"
				"</html>\r\n", jwtoken, qs_state);
	}
finished:
	FCGX_PutStr(dynstring_getcstring(&page), dynstring_length(&page), req->out);
	dynstring_free(&page);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

int process_debug_token_auth_request(FCGX_Request * req, HTTPUtils::RequestContext & req_ctx) {
	DynStringGuard jwt_content{};
	int res;
	char const * jwtoken_ptr = HTTPUtils_get_cookie(req_ctx.cookies, "auth", 0);
	std::string jwtoken = jwtoken_ptr ? jwtoken_ptr : "";
	if (jwtoken == "") {
		dynstring_appendstringz(jwt_content.ptr(), "NO CONTENT: ERROR\r\n", NULL);
	} else {
		std::unique_ptr<JWTUserContext> user_ctx = jwtinterface_getusercontext(jwtoken);
		if (user_ctx) {
			dynstring_appendstringz(jwt_content.ptr(), user_ctx->header_json_str.c_str(), "\r\n", NULL);
			dynstring_appendstringz(jwt_content.ptr(), user_ctx->payload_json_str_pretty.c_str(), "\r\n", NULL);
			fprintf(stderr, "process_debug_token_auth_request() %s\n", user_ctx->email_address.c_str());
		}
	}
	FCGX_FPrintF(req->out,
			"Status: 200\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"\r\n"
			"<!DOCTYPE html>\r\n"
			"<html>\r\n"
			"<head>\r\n"
			"<meta charset=\"UTF-8\" />\r\n"
			"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
			"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
			"<title>200 OK</title>\r\n"
			"</head>\r\n"
			"<body>\r\n"
			"<h1>200 OK</h1>\r\n"
			"<p>Contents of Supplied Token:</p>\r\n"
			"<pre>%s</pre>\r\n"
			"</body>\r\n"
			"</html>\r\n",
			jwt_content.c_str()
			);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

// TODO: guard dynstrings, almost had a leak.
static int process_logout_request(FCGX_Request * req, HTTPUtils::RequestContext & req_ctx) {
	char const * request_method = FCGX_GetParam("REQUEST_METHOD", req->envp);
	cookie_t * cookies = req_ctx.cookies;
	dynstring_context_t header_content = DYNSTRING_DEFAULT_INIT;
	dynstring_appendstringz(&header_content,
			"Status: 200\r\n", NULL);
	size_t idx = 0;
	if (cookies != NULL) {
		while (cookies[idx].name != NULL && cookies[idx].value != NULL) {
			dynstring_appendstringz(&header_content, "Set-Cookie: ", NULL);
			dynstringhtml_htmlspecial_encode_appendz(&header_content, cookies[idx].name);
			dynstring_appendstringz(&header_content, "=; Path=/; ", NULL);
			dynstring_appendstringz(&header_content, "Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; ", NULL);
			if (strcmp(cookies[idx].name, "auth") == 0) {
				dynstring_appendstringz(&header_content, "Secure; HttpOnly; SameSite=Lax", NULL);
			}
			dynstring_appendstringz(&header_content, "\r\n", NULL);
			idx = idx + 1;
		}
	}
	dynstring_appendstringz(&header_content,
			"Cache-Control: no-cache\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"\r\n", NULL);
#ifdef DO_DEBUG_STUFF
	dynstring_context_t page_content = DYNSTRING_DEFAULT_INIT;
	dynstring_appendstringz(&page_content,
			"<!DOCTYPE html>\r\n"
			"<html>\r\n"
			"<head>\r\n"
			"<meta charset=\"UTF-8\" />\r\n"
			"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
			"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
			"<title>200 OK</title>\r\n"
			"</head>\r\n"
			"<body>\r\n"
			"<h1>200 OK</h1>\r\n"
			"<p>request method:</p>\r\n"
			"<pre>", request_method, "</pre>\r\n"
			"<p>Cookie:</p>\r\n"
			"<pre>", NULL);
	idx = 0;
	while (cookies[idx].name != NULL && cookies[idx].value != NULL) {
		dynstringhtml_htmlspecial_encode_appendz(&page_content, cookies[idx].name);
		dynstring_appendstringz(&page_content, " = ", NULL);
		dynstringhtml_htmlspecial_encode_appendz(&page_content, cookies[idx].value);
		dynstring_appendstringz(&page_content, "\r\n", NULL);
		idx = idx + 1;
	}
	dynstring_appendstringz(&page_content,
			"</pre>\r\n"
			"<p>The cookies that are listed above, if any, should now have been removed.</p>\r\n"
			"<p><a href=\"https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=https%3A%2F%2Fportal.stockval.co.uk%2Fauth%2Fdebug\">Logout at Microsoft</a>.</p>\r\n"
			"</body>\r\n"
			"</html>\r\n",
			NULL
			);
	FCGX_PutStr(dynstring_getcstring(&header_content), dynstring_length(&header_content), req->out);
	FCGX_PutStr(dynstring_getcstring(&page_content), dynstring_length(&page_content), req->out);
	dynstring_free(&page_content);
#else
	//std::string page_content = application_logout_page_get_content();
	TemplateEngine templ{application_logout_page_get_content()};
	templ.SetVariable("APPLICATION_SERVICEPROVIDER_LOGOUT_URL", "https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=https%3A%2F%2Fportal.stockval.co.uk%2Fauth%2Fmicrosoft%2Flogout");
	std::string page_content = templ.Render();
	FCGX_PutStr(dynstring_getcstring(&header_content), dynstring_length(&header_content), req->out);
	FCGX_PutStr(page_content.c_str(), page_content.length(), req->out);
#endif // DO_DEBUG_STUFF
	dynstring_free(&header_content);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

int fcgx_prepare_request_context(FCGX_Request * req, HTTPUtils::RequestContext & req_ctx) {
	req_ctx.request_method = FCGX_GetParam("REQUEST_METHOD", req->envp);
	req_ctx.request_uri = FCGX_GetParam("REQUEST_URI", req->envp);
	req_ctx.script_name = FCGX_GetParam("SCRIPT_NAME", req->envp);
	req_ctx.path_info = FCGX_GetParam("PATH_INFO", req->envp);
	req_ctx.document_root = FCGX_GetParam("DOCUMENT_ROOT", req->envp);
	req_ctx.query_string = FCGX_GetParam("QUERY_STRING", req->envp);
	req_ctx.request_id = FCGX_GetParam("REQUEST_ID", req->envp);
	req_ctx.cookie = FCGX_GetParam("HTTP_COOKIE", req->envp);
	/* cookies disposed in ~RequestContext() */
	req_ctx.cookies = HTTPUtils_parse_cookies(req_ctx.cookie);
	req_ctx.authorisation = FCGX_GetParam("HTTP_AUTHORIZATION", req->envp);
	req_ctx.qs = querystring_decode_inplace(req_ctx.query_string);
	{
		int slashcount;
		std::string base_loc = "";
		slashcount = strutils_countchar(req_ctx.path_info.c_str(), '/', 0);
		for (int c = 0; c < slashcount; ++c) {
			base_loc = base_loc + "../";
		}
		req_ctx.base_loc = base_loc;
	}
	{
		if (auto path_info_parsed = HTTPUtils::parse_path(req_ctx.path_info.c_str())) {
			req_ctx.parsed_path = std::move(*path_info_parsed);
		}
	}
	return 0;
}

int appauth_process_request_ex(FCGX_Request * req) {
	HTTPUtils::RequestContext req_ctx{};
	fcgx_prepare_request_context(req, req_ctx);
	return 0;
}

int appauth_process_request(FCGX_Request * req) {
	char * request_method = FCGX_GetParam("REQUEST_METHOD", req->envp);
	char * path_info = FCGX_GetParam("PATH_INFO", req->envp);
	char * query_string = FCGX_GetParam("QUERY_STRING", req->envp);
	char * document_root = FCGX_GetParam("DOCUMENT_ROOT", req->envp);
	char * script_name = FCGX_GetParam("SCRIPT_NAME", req->envp);
	char * request_id = FCGX_GetParam("REQUEST_ID", req->envp);
	char * request_uri = FCGX_GetParam("REQUEST_URI", req->envp);
	int res;
	fprintf(stderr, "%s %s %s\n", request_id, request_method, request_uri);
	//fprintf(stderr, "REQUEST_METHOD %s\n", request_method);
	//fprintf(stderr, "REQUEST_URI %s\n", request_uri);
	//fprintf(stderr, "DOCUMENT_ROOT %s\nPATH_INFO %s\nQUERY_STRING %s\nSCRIPT_NAME %s\nREQUEST_ID %s\n", document_root, path_info, query_string, script_name, request_id);
	if (strcmp(request_method, "GET") == 0) {
		if (strcmp(path_info, "login") == 0) {
			res = process_login_page_get(req, query_string);
			fprintf(stderr, "process_login_page_get() %d\n", res);
			return 0;
		}
	}
	HTTPUtils::RequestContext req_ctx{};
	fcgx_prepare_request_context(req, req_ctx);
	if (strcmp(request_method, "POST") == 0) {
		// posting to /auth/login
		if (strcmp(path_info, "login") == 0) {
			res = process_login_page_post(req, req_ctx);
			fprintf(stderr, "process_login_page_post() %d\n", res);
			goto finished;
		}
		if (strcmp(path_info, "microsoft/logout") == 0) {
			res = process_logout_request(req, req_ctx);
			fprintf(stderr, "process_logout_request() %d\n", res);
			goto finished;
		}
		if (strcmp(path_info, "verify") == 0) {
			res = process_verification_request(req, req_ctx);
			fprintf(stderr, "process_verification_request() %d\n", res);
			goto finished;
		}
	} else
	if (strcmp(request_method, "GET") == 0) {
		if (strcmp(path_info, "microsoft") == 0) {
			res = process_code_response(req, req_ctx);
			fprintf(stderr, "process_code_response() %d\n", res);
			goto finished;
		}
		if (strcmp(path_info, "microsoft/logout") == 0) {
			res = process_logout_request(req, req_ctx);
			fprintf(stderr, "process_logout_request() %d\n", res);
			goto finished;
		}
		if (strcmp(path_info, "verify") == 0) {
			res = process_verification_request(req, req_ctx);
			fprintf(stderr, "process_verification_request() %d\n", res);
			goto finished;
		}
		if (strcmp(path_info, "direct") == 0) {
			res = process_direct_token_auth_request(req, req_ctx);
			fprintf(stderr, "process_direct_token_auth_request() %d\n", res);
			goto finished;
		}
		if (strcmp(path_info, "debug") == 0) {
			res = process_debug_token_auth_request(req, req_ctx);
			fprintf(stderr, "process_debug_token_auth_request() %d\n", res);
			goto finished;
		}
		if (strcmp(path_info, "logout") == 0) {
			res = process_logout_request(req, req_ctx);
			fprintf(stderr, "process_logout_request() %d\n", res);
			goto finished;
		}
	} else
	if (strcmp(request_method, "HEAD") == 0) {
		fprintf(stderr, "HEAD Request\n");
		FCGX_FPrintF(req->out,
				"Status: 403\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n");
		goto nearly_finished;
	}
	// this case when nothing matched, just terminate with 404
	FCGX_FPrintF(req->out,
			"Status: 404\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"\r\n");
nearly_finished:
	//FCGX_FClose(req->out);
	FCGX_Finish_r(req);
finished:
	return 0;
}

