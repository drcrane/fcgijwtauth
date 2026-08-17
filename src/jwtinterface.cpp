#include "jwtinterface.hpp"
#include <jwt-cpp/jwt.h>
#include <picojson/picojson.h>
#include "HTTPUtils.hpp"

std::string jwtinterface_get_token_from_cookie_or_authorization(char * cookies_str, char * auth_str) {
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
		//if (auth_str == NULL || *auth_str == '\0') {
		//}
		fprintf(stderr, "[Auth] Authorization header not currently parsed\n");
	}
	return jwt_str;
}

std::unique_ptr<JWTUserContext> jwtinterface_getusercontext(std::string & jwt_str) {
	std::unique_ptr<JWTUserContext> user_context = std::make_unique<JWTUserContext>();
	jwt::decoded_jwt<jwt::traits::kazuho_picojson> jwt = jwt::decode(jwt_str);
	std::map<std::string, picojson::value> payload_obj = jwt.get_payload_json();
	const picojson::value value = picojson::value(payload_obj);
	user_context->payload_json_str = value.serialize();
	//const picojson::object& payload_obj = payload.get<picojson::object>();
	//std::string payload_str = payload_obj.serialize();
	//std::string payload_str = payload.serialize();
	//user_context.get()->email_address = jwt.get_subject();
	//user_context.get()->friendly_name = jwt.get_payload_json();
	return user_context;
}

