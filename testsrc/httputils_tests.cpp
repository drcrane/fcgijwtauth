#include <iostream>
#include "../src/HTTPUtils.hpp"

int main() {
	std::string cookieHeader = "name1=value1; name2=value2; name3=value3";

	std::map<std::string, std::string> cookies = parse_cookies(cookieHeader);

	for (const auto& cookie : cookies) {
		std::cout << cookie.first << " = " << cookie.second << std::endl;
	}

	char hdr[] = "user=alice; session=xyz123; theme=dark";
	cookie_t *ck = HTTPUtils_parse_cookies(hdr);

	/* Access parsed cookies */
	for (int i = 0; ck[i].name; i++) {
		printf("Cookie %d: %s = %s\n", i, ck[i].name, ck[i].value);
	}

	/* Restore original header */
	HTTPUtils_restore_cookies(hdr, ck);
	printf("Restored header: %s\n", hdr);

	free(ck);

	char hdr2[] = "auth=Bearer eyJKS; signed_in=false;";
	ck = HTTPUtils_parse_cookies(hdr2);

	for (int i = 0; ck[i].name; i++) {
		fprintf(stderr, "%i: %s[%s]\n", i, ck[i].name, ck[i].value);
	}
	HTTPUtils_restore_cookies(hdr2, ck);
	fprintf(stderr, "%s\n", hdr2);
	free(ck);

	return 0;
}
