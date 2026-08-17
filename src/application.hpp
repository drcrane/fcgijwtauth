#ifndef APPLICATION_HPP
#define APPLICATION_HPP

#include <string>
#include <chrono>
#include <map>
#include <vector>
#include <optional>
#include "jwtinterface.hpp"
#include "JWKSVerifierStore.hpp"

//extern std::map<std::string, JWKSVerifierStore> g_store_map{};

std::string set_to_json(const std::set<std::string> & string_set);
std::string time_point_to_string(const std::chrono::system_clock::time_point & tp);
std::unique_ptr<JWTUserContext> verify_jwks_authentication_ex(JWKSStoreManager & store_man, char * cookies_str, char * auth_str);
int verify_jwks_authentication_jwt(JWKSStoreManager & store_man, std::string & jwt_str);
int verify_jwks_authentication(JWKSStoreManager & store_man, char * cookies_str, char * auth) ;
void application_template_init();
std::string & application_login_page_get_content();

#endif // APPLICATION_HPP
