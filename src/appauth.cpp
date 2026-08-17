#include <fcgiapp.h>
#include <stdio.h>
#include <cstdlib>
#include <string.h>
#include <map>
#include <optional>
#include <vector>
#include <chrono>
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

using json_traits = jwt::traits::kazuho_picojson;

JWKSStoreManager g_store_man{};

int get_tokens_from_microsoft(const char * code, char ** json, char ** token_ptr) {
	HttpResponse response = { .content_type = NULL, .data = NULL, .length = 0 };
	int res;
	dynstring_context_t post_data = DYNSTRING_DEFAULT_INIT;
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
					std::string token = token_json_value.get<std::string>();
					//fprintf(stderr, "> %s\n", token.c_str());
					*token_ptr = strdup(token.c_str());
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
int process_login_page_post(FCGX_Request * req, libgreen::QueryString * qs) {
	formdecoder_context * fd_ctx = NULL;
	formdecoder_decodefcgirequest(req, &fd_ctx, 1024*1024, NULL);
	// Check for valid input and then try and forward to the provider
	// (at this point we don't care too much about the email address provided
	// by the user)
	size_t provider_len = 0;
	char * provider = NULL;
	int res;
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
		//dynstring_context_t verifyable_salt = DYNSTRING_DEFAULT_INIT;
		//dynstringhtml_url_encode_appendz(&verifyable_salt, current_time.c_str());
		//openidconnect_create_verifyable_string(OAUTH2_DEFAULT_CLIENT_SECRET, dynstring_getcstring(&verifyable_salt), &verifyable_string);
		openidconnect_create_verifyable_string(OAUTH2_DEFAULT_CLIENT_SECRET, (send_to + '.' + current_time).c_str(), &verifyable_string);
		//dynstring_free(&verifyable_salt);
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
		dynstring_context_t page = DYNSTRING_DEFAULT_INIT;
		dynstring_appendstringz(&page,
#ifdef OPTION_NOREDIRECTS
				"Status: 200\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
#endif
#ifndef OPTION_NOREDIRECTS
				"Status: 302\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"Location: ", redirect_uri, "\r\n"
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
	}
	formdecoder_dispose(fd_ctx);
	FCGX_FFlush(req->out);
	FCGX_FClose(req->out);
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

int process_code_response(FCGX_Request * req, libgreen::QueryString * qs) {
	char const * qs_code = querystring_getbykey(qs->GetCtx(), "code");
	char const * qs_state = querystring_getbykey(qs->GetCtx(), "state");
	char * json = NULL;
	char * jwtoken = NULL;
	const char * redirect_url = NULL;
	std::string jwtoken_str;
	dynstring_context_t page = DYNSTRING_DEFAULT_INIT;
	if (qs_code == NULL || qs_state == NULL) {
		dynstring_appendstringz(&page,
				"Status: 400\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html><head></head><body>\r\n"
				"<h1>400 Error</h1>\r\n"
				"<p>Seems that no code or state argument were supplied.</p>\r\n"
				"</body></html>\r\n",
				NULL);
		goto finished;
	}
	int res;
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
				"<html><head></head><body>\r\n"
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
			"Set-Cookie: auth=", jwtoken, "; Path=/; Secure; HttpOnly; SameSite=Strict\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
#endif
#ifndef OPTION_NOREDIRECTS
			"Status: 302\r\n"
			"Set-Cookie: auth=", jwtoken, "; Path=/; Secure; HttpOnly; SameSite=Strict\r\n"
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

int process_verification_request(FCGX_Request * req, libgreen::QueryString * qs) {
	// Look for an Authorization header or Cookie
	char * authorisation = FCGX_GetParam("HTTP_AUTHORIZATION", req->envp);
	char * cookie = FCGX_GetParam("HTTP_COOKIE", req->envp);
	int res = 0;
	fprintf(stderr, "Authorization: %s\n", authorisation);
	fprintf(stderr, "Cookie: %s\n", cookie);
	if ((cookie != NULL || authorisation != NULL) && (res = verify_jwks_authentication(g_store_man, cookie, authorisation)) == 0) {
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
		FCGX_FPrintF(req->out, "Status: 401 Unauthorized\r\n"
		//FCGX_FPrintF(req->out, "Status: 403 Forbidden\r\n"
			"WWW-Authenticate: Bearer realm=\"private_files\" scope=\"openid profile email\"\r\n"
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
	}
	FCGX_FFlush(req->out);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

int process_login_page_get(FCGX_Request * req, char * query_string) {
	dynstring_context_t page = DYNSTRING_DEFAULT_INIT;
	char * authorisation = FCGX_GetParam("HTTP_AUTHORIZATION", req->envp);
	char * cookie = FCGX_GetParam("HTTP_COOKIE", req->envp);
	int res;
	fprintf(stderr, "Authorization: %s\n", authorisation);
	fprintf(stderr, "Cookie: %s\n", cookie);
	const char * return_to = NULL;
	//return_to = querystring_getbykey(qs->GetCtx(), "return");
	if (query_string != NULL && strlen(query_string) >= 8) {
		if (strncmp(query_string, "return=", 7) == 0 && query_string[7] == '/' && query_string[8] != '/') {
			return_to = query_string + 7;
		}
	}
	if (return_to == NULL) {
//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wwrite-strings"
		return_to = "/";
//#pragma GCC diagnostic pop
	}
	fprintf(stderr, "Redirecting To: %s\n", return_to);
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

	std::string & login_page = application_login_page_get_content();
	TemplateEngine templ = TemplateEngine();
	templ.SetTemplate(login_page);
	templ.SetVariable("REDIRECT_URL", std::string(return_to));
	std::string & final_page = templ.Render();
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

int process_direct_token_auth_request(FCGX_Request * req, libgreen::QueryString * qs) {
	dynstring_context_t page = DYNSTRING_DEFAULT_INIT;
	char const * jwtoken;
	std::string jwtoken_str;
	int res = 0;
	jwtoken = querystring_getbykey(qs->GetCtx(), "token");
	if (jwtoken == NULL) {
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
	FCGX_FPrintF(req->out, "Status: 200\r\n"
			"Set-Cookie: auth=%s; Path=/; Secure; HttpOnly; SameSite=Strict\r\n"
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
			"</body>\r\n"
			"</html>\r\n", jwtoken);
finished:
	FCGX_PutStr(dynstring_getcstring(&page), dynstring_length(&page), req->out);
	dynstring_free(&page);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

int process_debug_token_auth_request(FCGX_Request * req, libgreen::QueryString * qs) {
	char * authorisation = FCGX_GetParam("HTTP_AUTHORIZATION", req->envp);
	char * cookie = FCGX_GetParam("HTTP_COOKIE", req->envp);
	dynstring_context_t jwt_content = DYNSTRING_DEFAULT_INIT;
	int res;
	fprintf(stderr, "process_debug_token_auth_request() ---- ---- ----\n");
	fprintf(stderr, "Authorization: %s\n", authorisation);
	fprintf(stderr, "Cookie: %s\n", cookie);
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
			dynstring_getcstring(&jwt_content)
			);
	dynstring_free(&jwt_content);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

int appauth_process_request(FCGX_Request * req) {
	char * request_method = FCGX_GetParam("REQUEST_METHOD", req->envp);
	char * path_info = FCGX_GetParam("PATH_INFO", req->envp);
	char * query_string = FCGX_GetParam("QUERY_STRING", req->envp);
	char * document_root = FCGX_GetParam("DOCUMENT_ROOT", req->envp);
	char * script_name = FCGX_GetParam("SCRIPT_NAME", req->envp);
	char * request_id = FCGX_GetParam("REQUEST_ID", req->envp);
	int res;
	fprintf(stderr, "REQUEST_METHOD %s\n", request_method);
	fprintf(stderr, "DOCUMENT_ROOT %s\nPATH_INFO %s\nQUERY_STRING %s\nSCRIPT_NAME %s\nREQUEST_ID %s\n", document_root, path_info, query_string, script_name, request_id);
	if (strcmp(request_method, "GET") == 0) {
		if (strcmp(path_info, "login") == 0) {
			res = process_login_page_get(req, query_string);
			fprintf(stderr, "process_login_page_get() %d\n", res);
			return 0;
		}
	}
	libgreen::QueryString qs(query_string);
	if (strcmp(request_method, "POST") == 0) {
		// posting to /auth/login
		if (strcmp(path_info, "login") == 0) {
			res = process_login_page_post(req, &qs);
			fprintf(stderr, "process_login_page_post() %d\n", res);
			goto finished;
		}
	}
	if (strcmp(request_method, "GET") == 0) {
		if (strcmp(path_info, "microsoft") == 0) {
			res = process_code_response(req, &qs);
			fprintf(stderr, "process_code_response() %d\n", res);
			goto finished;
		}
		if (strcmp(path_info, "verify") == 0) {
			res = process_verification_request(req, &qs);
			fprintf(stderr, "process_verification_request() %d\n", res);
			goto finished;
		}
		if (strcmp(path_info, "direct") == 0) {
			res = process_direct_token_auth_request(req, &qs);
			fprintf(stderr, "process_direct_token_auth_request() %d\n", res);
			goto finished;
		}
		if (strcmp(path_info, "debug") == 0) {
			res = process_debug_token_auth_request(req, &qs);
			fprintf(stderr, "process_debug_token_auth_request() %d\n", res);
			goto finished;
		}
	}
	// this case when nothing matched, just terminate with 404
	FCGX_FPrintF(req->out,
			"Status: 404\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"\r\n");
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
finished:
	return 0;
}

