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
#include "appauth.hpp"

int main(int argc, char *argv[]) {
	FCGX_Request * req;
	int rc;

	//g_store_man.emplace("https://testingid.e42.uk", "./conf/e42_uk.jwks.json");
	//g_store_man.emplace("https://login.microsoft.com", "./conf/");
	//g_store_man.fetch_jwks_json("https://login.microsoftonline.com/common/discovery/v2.0/keys", "./conf/microsoft.jwks.json");
	{
		time_t last_time = 0L;
		//JWKSStore * store = g_store_man.add_jwks_verifiers_from_string("microsoft", "https://login.microsoftonline.com/common/discovery/v2.0/keys", g_store_man.fetch_jwks_json("./conf/microsoft.jwks.json", &last_time));
		JWKSStore * store = g_store_man.get_or_create_store("microsoft");
		store->backing_file_ = "./conf/microsoft.jwks.json";
		store->src_url_ = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
		//store->last_fetch_time_ = std::chrono::system_clock::from_time_t(0);
		std::string jwks_string = g_store_man.fetch_jwks_json(store->backing_file_, &last_time);
		store->add_jwks_verifiers_from_string(jwks_string);
		store->last_fetch_time_ = std::chrono::system_clock::time_point{std::chrono::seconds{last_time}};
		//if (store != nullptr) {
		//	store->last_fetch_time_ = std::chrono::system_clock::time_point{std::chrono::seconds{last_time}};
		//}
	}
	//JWKSStore * store = g_store_man.find_store("microsoft");
	//if (store == nullptr) {
	//	store->add_jwks_verifiers_from_string(g_store_man.fetch_jwks_json("./conf/microsoft.jwks.json"));
	//}
	application_template_init();

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
		rc = appauth_process_request(req);
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

