#ifndef JWTINTERFACE_HPP
#define JWTINTERFACE_HPP

#include <string>
#include <memory>

struct JWTUserContext {
	std::string friendly_name;
	std::string email_address;
	std::string payload_json_str;
};

std::string jwtinterface_get_token_from_cookie_or_authorization(char * cookies_str, char * auth_str);
std::unique_ptr<JWTUserContext> jwtinterface_getusercontext(std::string & jwt_str);

#endif // JWTINTERFACE_HPP

