#ifndef HTTPUTILS_H
#define HTTPUTILS_H

#include <string>
#include <map>

//std::map<std::string, std::string> parse_cookies(std::string& cookie_header);

// TODO: Implement some kind of RAII thingy like DynStringGuard.

extern "C" {

typedef struct {
	char * name;
	char * value;
} cookie_t;

cookie_t * HTTPUtils_parse_cookies(char * header);
void HTTPUtils_dispose_cookies(cookie_t * cookies);
void HTTPUtils_restore_cookies(char * header, cookie_t * cookies);
char const * HTTPUtils_get_cookie(cookie_t * cookies, char const * name, size_t idx);

};

#endif // HTTPUTILS_H

