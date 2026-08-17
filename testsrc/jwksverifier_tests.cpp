#include "../src/JWKSVerifierStore.hpp"
#include <iostream>

#define JWT "eyJhbGciOiJFUzI1NiIsImtpZCI6IiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImNvbXB1dGVyLnVzZXJAZXhhbXBsZS5jb20iLCJleHAiOjE3NDQ5NjQ3MzQsImlhdCI6MTc0NDg3ODMzNCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsImp0aSI6IlVSbVBTN2JLaUFzOUZSS2JRdnNmd01PY0VFVEpPb2dTIiwibmFtZSI6IkNvbXB1dGVyIFVzZXIiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic3ViIjoiY29tcHV0ZXIudXNlckBleGFtcGxlLmNvbSIsIndlYnNpdGUiOiJodHRwczovL2V4YW1wbGUuY29tLyJ9.ahiXY5-KzSfAiqNeQ80DYL0q_NqEXUYeAl3qWhMgrpLrUbS90YSWBkxcbm2Qiw5iTcBuWkOXF1rnkuls9F4fLw"

int main(int argc, char *argv[]) {
	JWKSStoreManager store{}; // "./testdata/ec256-private.jwks.json");
	std::string jwks_json = store.fetch_jwks_json("./testdata/ec256-private.jwks.json", nullptr);
	store.add_jwks_verifiers_from_string("microsoft", "./testdata/ec256-private.jwks.json", jwks_json);
	auto decoded_jwt = jwt::decode(JWT);
	std::string issuer = decoded_jwt.get_issuer();
	std::cerr << "Issued by: " << issuer << "\n";
	std::cerr << "header: " << decoded_jwt.get_header() << "\n";
	std::cerr << "kid: " << decoded_jwt.get_key_id() << "\n";
	auto issued_at = decoded_jwt.get_issued_at();
	auto issued_at_time_t = std::chrono::system_clock::to_time_t(issued_at);
	auto issued_at_timestamp = std::chrono::duration_cast<std::chrono::seconds>(issued_at.time_since_epoch()).count();
	std::string issued_at_iso8601;
	{
		char buffer[32];
		std::tm tm{};
		gmtime_r(&issued_at_time_t, &tm);
		std::strftime( buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
		issued_at_iso8601 = std::string(buffer);
	}
	std::cerr << "iat: " << issued_at_iso8601 << '\n';
	JWKSStore::Verifier * verifier = store.get_verifier(issuer, "947a627d87183f94388b39d71db6601679995a1f");
	if (verifier == NULL) {
		fprintf(stderr, "verifier not found\n");
		return 127;
	}
	// this will probably fail as the token above is probably expired
	try {
		verifier->verify(decoded_jwt);
	} catch (std::exception & ex) {
		fprintf(stderr, "%s\n", ex.what());
	}
}

