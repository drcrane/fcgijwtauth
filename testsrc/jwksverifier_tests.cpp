#include "../src/JWKSVerifierStore.hpp"
#include <iostream>

#define JWT "eyJhbGciOiJFUzI1NiIsImtpZCI6IiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImNvbXB1dGVyLnVzZXJAZXhhbXBsZS5jb20iLCJleHAiOjE3NDQ5NjQ3MzQsImlhdCI6MTc0NDg3ODMzNCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsImp0aSI6IlVSbVBTN2JLaUFzOUZSS2JRdnNmd01PY0VFVEpPb2dTIiwibmFtZSI6IkNvbXB1dGVyIFVzZXIiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic3ViIjoiY29tcHV0ZXIudXNlckBleGFtcGxlLmNvbSIsIndlYnNpdGUiOiJodHRwczovL2V4YW1wbGUuY29tLyJ9.ahiXY5-KzSfAiqNeQ80DYL0q_NqEXUYeAl3qWhMgrpLrUbS90YSWBkxcbm2Qiw5iTcBuWkOXF1rnkuls9F4fLw"

int main(int argc, char *argv[]) {
	JWKSVerifierStore store("./testdata/ec256-private.jwks.json");
	const JWKSVerifierStore::Verifier& verifier = store.get_verifier("947a627d87183f94388b39d71db6601679995a1f");
	auto decoded_jwt = jwt::decode(JWT);
	std::cerr << "Issued by: " << decoded_jwt.get_issuer() << "\n";
	// this will probably fail as the token above is probably expired
	verifier.verify(decoded_jwt);
}
