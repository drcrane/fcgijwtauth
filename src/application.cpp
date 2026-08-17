#include <map>
#include <optional>
#include <vector>
#include <chrono>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include "../src/HTTPUtils.hpp"
#include "jwt-cpp/jwt.h"
#include "jwt-cpp/traits/kazuho-picojson/traits.h"
#include "../src/JWKSVerifierStore.hpp"
#include "application.hpp"
#include "simpletemplate.hpp"
#include "appspecific.h"
#include "jwtinterface.hpp"

std::string set_to_json(const std::set<std::string> & string_set) {
	picojson::array json_array;
	json_array.reserve(string_set.size());
	for (const auto& str : string_set) {
		json_array.emplace_back(str);
	}
	return picojson::value(json_array).serialize();
}

std::string time_point_to_string(const std::chrono::system_clock::time_point & tp) {
	auto time_t = std::chrono::system_clock::to_time_t(tp);
	std::stringstream ss;
	//ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
	ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S");
	return ss.str();
}

int verify_jwks_authentication_jwt(JWKSStoreManager & store_man, std::string & jwt_str) {
	try {
		jwt::decoded_jwt<jwt::traits::kazuho_picojson> jwt = jwt::decode(jwt_str);
		std::string typ = jwt.get_type();
		std::string algorithm = jwt.get_algorithm();
		std::string key_id = jwt.get_key_id();
		fprintf(stderr, "typ: %s\n"
				"alg: %s\n"
				"kid: %s\n",
				typ.c_str(), algorithm.c_str(), key_id.c_str());
		std::string issuer = jwt.get_issuer();
		std::string aud = jwt.has_payload_claim("aud") ? set_to_json(jwt.get_audience()) : "<no aud>";
		fprintf(stderr, "iss: %s\n"
				"aud: %s\n",
				issuer.c_str(), aud.c_str());
		//g_store_map.count(issuer);
		//std::map<std::string, JWKSVerifierStore>::iterator element = store_map.find("https://login.microsoft.com");
		//std::map<std::string, JWKSVerifierStore>::iterator element = store_map.find(issuer);
		//if (element == store_map.end()) {
		//	fprintf(stderr, "Issuer not found in map, looked for %s\n", issuer.c_str());
		//	return 2;
		//}
		// exception will be thrown here if no verifier is found
		//const JWKSVerifierStore::Verifier & verifier = element->second.get_verifier(jwt.get_key_id());
		//verifier.verify(jwt);
		//JWKSStore::Verifier * verifier = store_man.get_verifier(issuer, jwt.get_key_id());
		//if (verifier == nullptr) {
		//	fprintf(stderr, "Could not find verifier for key: %s - %s\n", issuer.c_str(), jwt.get_key_id().c_str());
		//	return 2;
		//}
		bool verify_res = store_man.verify_jwt("microsoft", jwt_str);
		fprintf(stderr, "Verification attempt result %s\n", verify_res ? "SUCCESS" : "FAILURE");
		if (verify_res == false) {
			return 2;
		}
		// Signature Valid but the token may be out of date
		std::chrono::time_point issue_time_date = jwt.get_issued_at();
		fprintf(stdout, "issued: %s\n", time_point_to_string(issue_time_date).c_str());
		std::chrono::time_point valid_until_date = jwt.get_expires_at();
		fprintf(stdout, "expires: %s\n", time_point_to_string(valid_until_date).c_str());
		return 0;
	} catch (std::runtime_error & re) {
		fprintf(stderr, "[Auth] Something wrong with jwt (%s)\n", jwt_str.c_str());
	}
	return 1;
}

int verify_jwks_authentication(JWKSStoreManager & store_man, char * cookies_str, char * auth_str) {
	std::string jwt_str = jwtinterface_get_token_from_cookie_or_authorization(cookies_str, auth_str);
	return verify_jwks_authentication_jwt(store_man, jwt_str);
}

TemplateEngine application_login_page = TemplateEngine("htdocs/login_template.html");

void application_template_init() {
	application_login_page.SetVariable("WELCOME_TO_COMPANY_NAME", APPLICATION_WELCOME_TO_COMPANY_NAME);
	application_login_page.SetVariable("APPLICATION_NAME", APPLICATION_APPLICATION_NAME);
	application_login_page.SetVariable("PRIVACY_POLICY_URL", APPLICATION_PRIVACY_POLICY_URL);
	return;
}

std::string & application_login_page_get_content() {
	return application_login_page.Render();
}

/* ************************************************************************* */
/* Below are the main application functions                                  */
/* ************************************************************************* */

