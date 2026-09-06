#include "jwtinterface.hpp"
#include <jwt-cpp/jwt.h>
#include <picojson/picojson.h>
#include "HTTPUtils.hpp"
#include <sstream>

static int get_string(const std::map<std::string, picojson::value> & obj, const std::string & key, std::string & result) {
	auto it = obj.find(key);
	if (it == obj.end() || !it->second.is<std::string>()) {
		return -1;
	}
	result = it->second.get<std::string>();
	return 0;
}

std::string jwtinterface_get_token_from_cookie(cookie_t * cookies) {
	std::string jwt_str{};
	if (cookies != NULL) {
		for (size_t i = 0; cookies[i].name != NULL; ++i) {
			if (strcmp(cookies[i].name, "auth") == 0) {
				jwt_str = cookies[i].value;
			}
		}
	}
	return jwt_str;
}

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
		HTTPUtils_dispose_cookies(cookies);
	}
	if (jwt_str.empty()) {
		// TODO: try to get the jwt from the Authentication header.
		//if (auth_str == NULL || *auth_str == '\0') {
		//}
		fprintf(stderr, "[Auth] Authorization header not currently parsed\n");
	}
	return jwt_str;
}


static std::string prettyPrintObject(const picojson::object& obj)
{
    if (obj.empty()) {
        return "{}";
    }

    std::ostringstream out;
    out << "{\n";

    bool first = true;
    for (const auto& member : obj) {
        if (!first) {
            out << ",\n";
        }
        first = false;

        // The key must be a JSON string, so serialize it too.
        // This adds quotes and escapes characters like quotes/backslashes.
        out << "  "
            << picojson::value(member.first).serialize()
            << ": "
            << member.second.serialize();
    }

    out << "\n}";
    return out.str();
}

std::unique_ptr<JWTUserContext> jwtinterface_getusercontext(std::string & jwt_str) {
	std::unique_ptr<JWTUserContext> user_context = std::make_unique<JWTUserContext>();
	jwt::decoded_jwt<jwt::traits::kazuho_picojson> jwt = jwt::decode(jwt_str);
	std::map<std::string, picojson::value> payload_obj = jwt.get_payload_json();
	int res;
	res = get_string(payload_obj, "email", user_context->email_address);
	if (res != 0) {
		return nullptr;
	}
	res = get_string(payload_obj, "name", user_context->friendly_name);
	if (res != 0) {
		return nullptr;
	}
	const picojson::value value = picojson::value(payload_obj);
	user_context->payload_json_str = value.serialize();
	user_context->payload_json_str_pretty = prettyPrintObject(payload_obj);
	//const picojson::object& payload_obj = payload.get<picojson::object>();
	//std::string payload_str = payload_obj.serialize();
	//std::string payload_str = payload.serialize();
	//user_context.get()->email_address = jwt.get_subject();
	//user_context.get()->friendly_name = jwt.get_payload_json();
	const picojson::value header_json = picojson::value(jwt.get_header_json());
	user_context->header_json_str = header_json.serialize();
	return user_context;
}

