#include <cstdlib>
#include <stdio.h>
#include <openssl/rand.h>
#include "jwt-cpp/traits/kazuho-picojson/traits.h"
#include "jwt-cpp/jwt.h"
#include "picojson/picojson.h"
#include "../src/JWKSVerifierStore.hpp"

using json_traits = jwt::traits::kazuho_picojson;

int main(int argc, char *argv[]) {
	char * name = NULL;
	char * email = NULL;
	char * issuer = (char *)"https://testingid.e42.uk";
	char * kid = (char *)"947a627d87183f94388b39d71db6601679995a1f";
	for (int i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "--name") == 0) {
			++i;
			name = argv[i];
		}
		if (strcmp(argv[i], "--email") == 0) {
			++i;
			email = argv[i];
		}
		if (strcmp(argv[i], "--issuer") == 0) {
			++i;
			issuer = argv[i];
		}
		if (strcmp(argv[i], "--kid") == 0) {
			++i;
			kid = argv[i];
		}
	}

	if (email == NULL) {
		fprintf(stderr, "please supply --email argument\n");
		return EXIT_FAILURE;
	}
	if (name == NULL) {
		fprintf(stderr, "please supply --name argument\n");
		return EXIT_FAILURE;
	}

	std::cerr << "issuer: " << issuer << "\n";
	std::cerr << "kid: " << kid << "\n";

	JWKSVerifierStore store = JWKSVerifierStore("./conf/e42_uk.jwks.json");
	json_traits::object_type jwk = store.get_jwk(kid);
	const std::string & x = jwk.at("x").get<std::string>();
	const std::string & y = jwk.at("y").get<std::string>();
	const std::string & d = jwk.at("d").get<std::string>();

	std::cerr << "x: " << x << "\n";
	std::cerr << "y: " << y << "\n";
	std::cerr << "d: " << d << "\n";
	auto pem_priv_key = JWKSVerifierStore::create_pem_ec_key(x, y, d);

	std::cerr << pem_priv_key << "\n";

	unsigned char nonce[24];
	RAND_bytes(nonce, sizeof(nonce));
	std::string jti = jwt::base::encode<jwt::alphabet::base64url>(std::string{reinterpret_cast<const char*>(nonce), sizeof(nonce)});

	std::string token = jwt::create<jwt::traits::kazuho_picojson>()
							.set_type("JWT")
							.set_key_id(kid)
							.set_id(jti)
							.set_issuer(issuer)
							.set_subject(email)
							.set_issued_at(std::chrono::system_clock::now())
							.set_expires_at(std::chrono::system_clock::now() + std::chrono::hours{24 * 28})
							.set_payload_claim("name", picojson::value(std::string{name}))
							.set_payload_claim("email", picojson::value(std::string{email}))
							.sign(jwt::algorithm::es256("", pem_priv_key, "", ""));
	std::cerr << token << "\r\n";

	json_traits::object_type claims = json_traits::object_type{};
	//json::object_type claims;
	//picojson::object object;
	//picojson::object claims{};
	//claims.insert(
	//store.make_jwt();
	if (name != NULL) {
		claims["name"] = json_traits::value_type(name);
	}
	if (email != NULL) {
		claims["email"] = picojson::value(email);
	}
	std::string claimsString = picojson::value(claims).serialize(false);
	std::cerr << claimsString << "\n";

	return 0;
}
