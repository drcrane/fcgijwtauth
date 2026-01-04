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
#include "../src/HTTPUtils.hpp"
#include "jwt-cpp/jwt.h"
#include "jwt-cpp/traits/kazuho-picojson/traits.h"
#include "../src/JWKSVerifierStore.hpp"

using json_traits = jwt::traits::kazuho_picojson;

/* map contains a map of issuers and stores for that issuer */
std::map<std::string, JWKSVerifierStore> g_store_map{};

std::string set_to_json(const std::set<std::string>& string_set) {
	picojson::array json_array;
	json_array.reserve(string_set.size());
	
	for (const auto& str : string_set) {
		json_array.emplace_back(str);
	}
	
	return picojson::value(json_array).serialize();
}

std::string time_point_to_string(const std::chrono::system_clock::time_point& tp) {
	auto time_t = std::chrono::system_clock::to_time_t(tp);
	std::stringstream ss;
	//ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
	ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S");
	return ss.str();
}

int verify_jwks_authentication(char * cookies_str, char * auth) {
	cookie_t * cookies;
	std::string jwt_str{};
	cookies = HTTPUtils_parse_cookies(cookies_str);
	if (cookies != NULL) {
		for (int i = 0; cookies[i].name != NULL; ++i) {
			if (strcmp(cookies[i].name, "auth") == 0) {
				// we found a possible jwt
				jwt_str = std::string(cookies[i].value);
			}
		}
		free(cookies);
	}
	if (jwt_str.empty()) {
		// TODO: try to get the jwt from the Authentication header.
		if (auth == NULL || *auth == '\0') {
			fprintf(stderr, "[Auth] Authorization header not currently parsed\n");
		}
	}
	try {
		jwt::decoded_jwt<jwt::traits::kazuho_picojson> jwt = jwt::decode(jwt_str);
		std::string issuer = jwt.get_issuer();
		std::string algorithm = jwt.get_algorithm();
		std::string aud = jwt.has_payload_claim("aud") ? set_to_json(jwt.get_audience()) : "<no aud>";
		fprintf(stderr, "iss: %s\n"
			"alg: %s\n"
			"aud: %s\n"
			/*"alg: %s\n"*/,
			issuer.c_str(), algorithm.c_str(), aud.c_str());
		//g_store_map.count(issuer);
		std::map<std::string, JWKSVerifierStore>::iterator element = g_store_map.find(issuer);
		if (element == g_store_map.end()) {
			return 2;
		}
		// exception will be thrown here if no verifier is found
		const JWKSVerifierStore::Verifier & verifier = element->second.get_verifier(jwt.get_key_id());
		verifier.verify(jwt);
		// Signature Valid but the token may be out of date
		std::chrono::time_point issue_time_date = jwt.get_issued_at();
		fprintf(stdout, "issued: %s\n", time_point_to_string(issue_time_date).c_str());
		return 0;
	} catch (std::runtime_error & re) {
		fprintf(stderr, "[Auth] Something wrong with jwt (%s)\n", jwt_str.c_str());
	}
	return 1;
}

int process_request(FCGX_Request * req) {
	char * authorisation = FCGX_GetParam("HTTP_AUTHORIZATION", req->envp);
	char * cookie = FCGX_GetParam("HTTP_COOKIE", req->envp);
	fprintf(stderr, "Authorization: %s\n", authorisation);
	fprintf(stderr, "Cookie: %s\n", cookie);
	int res;
	if ((cookie != NULL || authorisation != NULL) && (res = verify_jwks_authentication(cookie, authorisation)) == 0) {
		FCGX_FPrintF(req->out, "Status: 200\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"\r\n"
				"<!DOCTYPE html>\r\n"
				"<html>\r\n"
				"<head>\r\n"
				"<title>Authorisation</title>\r\n"
				"</head>\r\n"
				"<body>\r\n"
				"<h1>Authorisation (%d)</h1>\r\n"
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

int main(int argc, char *argv[]) {
	FCGX_Request * req;
	int rc;

	g_store_map.emplace("https://testingid.e42.uk", "./conf/e42_uk.jwks.json");

	FCGX_Init();
	req = (FCGX_Request *)malloc(sizeof(FCGX_Request));
	if (req == NULL) {
		fprintf(stderr, "main(): malloc() error\n");
		goto error;
	}
	do {
		FCGX_InitRequest(req, 0, 0);
		rc = FCGX_Accept_r(req);
		if (rc != 0) {
			fprintf(stderr, "main(): FCGX_Accept_r(req) %d\n", rc);
			break;
		}
		rc = process_request(req);
		if (rc != 0) {
			fprintf(stderr, "main(): process_request(req) %d\n", rc);
			break;
		}
	} while (1);
	free(req);
	req = NULL;
	return EXIT_SUCCESS;
error:
	return EXIT_FAILURE;
}

