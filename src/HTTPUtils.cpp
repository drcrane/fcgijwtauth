#include "HTTPUtils.hpp"
#include <sstream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <span>


/*
std::string trim(const std::string& str) {
	size_t start = str.find_first_not_of(" \t\n\r\f\v");
	size_t end = str.find_last_not_of(" \t\n\r\f\v");
	return str.substr(start, (end - start + 1));
}

std::vector<std::string> split(const std::string & str, char delimiter) {
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(str);
	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(trim(token));
	}
	return tokens;
}

std::map<std::string, std::string> parse_cookies(std::string & cookie_header) {
	std::map<std::string, std::string> cookies;

	std::vector<std::string> cookiePairs = split(cookie_header, ';');

	for (const auto& pair : cookiePairs) {
		std::vector<std::string> nameValue = split(pair, '=');
		if (nameValue.size() == 2) {
			cookies[nameValue[0]] = nameValue[1];
		}
	}

	return cookies;
}
*/

#include <string.h>
#include <stdlib.h>

cookie_t * HTTPUtils_parse_cookies(char * header) {
	/* First pass: count segments separated by ';' */
	if (header == NULL) {
		return NULL;
	}
	int count = 0;
	for (char *p = header; ; ) {
		count++;
		char *sep = strchr(p, ';');
		if (!sep) break;
		p = sep + 1;
	}

	/* Allocate (count + 1) entries, including terminator */
	cookie_t * cookies = (cookie_t *)malloc((count + 1) * sizeof(cookie_t));
	if (!cookies) return NULL;

	/* Second pass: split into name/value */
	int idx = 0;
	for (char * p = header; *p && idx < count; idx++) {
		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
			++ p;
		}
		cookies[idx].name = p;
		/* Find '=' and terminate name */
		char * eq = strchr(p, '=');
		if (!eq) break;
		*eq = '\0';

		/* Value starts after '=' */
		char * val = eq + 1;
		cookies[idx].value = val;

		/* Find ';' and terminate value */
		char * semi = strchr(val, ';');
		if (semi) {
			*semi = '\0';
			p = semi + 1;
		} else {
			/* Last cookie */
			p = val + strlen(val);
		}
	}

	/* Terminator */
	cookies[idx].name  = NULL;
	cookies[idx].value = NULL;
	return cookies;
}

void HTTPUtils_dispose_cookies(cookie_t * cookies) {
	free(cookies);
}

char const * HTTPUtils_get_cookie(cookie_t * cookies, char const * name, size_t idx) {
	if (cookies == NULL) {
		return NULL;
	}
	while (cookies->name != NULL && cookies->value != NULL) {
		if (strcmp(cookies->name, name) == 0) {
			if (idx) {
				idx = idx - 1;
				continue;
			}
			return cookies->value;
		}
		cookies ++;
	}
	return NULL;
}

/*
 * restore_cookies:
 *   header: original buffer mutated by parse_cookies
 *   cookies: array returned by parse_cookies
 * Restores '=' and ';' into header.
 */
void HTTPUtils_restore_cookies(char * header, cookie_t * cookies) {
	for (int i = 0; cookies[i].name; i++) {
		char * value = cookies[i].value;

		/* Re‑insert '=' before value */
		*(value - 1) = '=';

		/* Compute end of this value */
		char * end = value + strlen(value);
		/* For all but last cookie, re‑insert ';' */
		if (cookies[i + 1].name) {
			*end = ';';
		}
	}
}

namespace HTTPUtils {

/*
 * This parser does not support empty segments, the following is fine:
 * /client/8472/job//2026-09-20.0001
 * but will be parsed as:
 * [ "client", "8472", "job", "2026-09-20.0001" ]:
 */
std::optional<ParsedPath> parse_path(std::string_view raw) {
	if (raw.empty()) {
		return std::nullopt;
	}
	if (!raw.empty() && raw.back() == '/') {
		raw.remove_suffix(1);
	}

	ParsedPath out;
	// Decoding can only shrink, so raw.size() is a hard upper bound.
	// Reserve once; no reallocation can occur during the loop.
	// But MAY be copied!
	out.storage.reserve(raw.size());

	std::vector<ParsedPath::Range> & ranges = out.ranges;

	std::size_t start = 0;
	while (start <= raw.size()) {
		const std::size_t slash = raw.find('/', start);
		std::string_view seg = (slash == std::string_view::npos)
			? raw.substr(start)
			: raw.substr(start, slash - start);

		if (!seg.empty()) {
			const std::size_t offset = out.storage.size();
			if (!detail::append_percent_decoded(seg, out.storage)) {
				return std::nullopt;
			}
			ranges.push_back({offset, out.storage.size() - offset});
		}

		if (slash == std::string_view::npos) break;
		start = slash + 1;
	}

	return out;
}

std::optional<ParsedPath> parse_path(const char * raw) {
	if (raw == nullptr) return std::nullopt;
	return parse_path(std::string_view{raw});
}

bool consume(const HTTPUtils::ParsedPath & parsed_path, std::size_t & idx, std::string_view literal) {
	if (idx >= parsed_path.size() || parsed_path.get_idx(idx) != literal) {
		return false;
	}
	idx = idx + 1;
	return true;
}

} // namespace HTTPUtils

