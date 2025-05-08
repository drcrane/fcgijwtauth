#ifndef HTTPUTILS_H
#define HTTPUTILS_H

#include <string>
#include <map>

std::map<std::string, std::string> parse_cookies(std::string& cookie_header);

extern "C" {

typedef struct {
	char *name;
	char *value;
} cookie_t;

cookie_t * HTTPUtils_parse_cookies(char * header);
void HTTPUtils_restore_cookies(char * header, cookie_t * cookies);

};

#endif // HTTPUTILS_H

