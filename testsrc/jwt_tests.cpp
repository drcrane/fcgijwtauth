#include "jwt-cpp/jwt.h"
#include "picojson/picojson.h"
#include "openssl/rand.h"
#include <stdio.h>
#include <string>
#include <fstream>
#include <sstream>
#include <chrono>
#include <stdexcept>
#include <filesystem>

static std::string read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    std::string content;
    content.resize(std::filesystem::file_size(filename));
    file.read(content.data(), content.size());
    return content;
}

std::string load_file_to_string(const std::string& filename) {
    std::ifstream file_stream(filename, std::ios::in | std::ios::binary);
        if (!file_stream) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    std::ostringstream buffer;
    buffer << file_stream.rdbuf();
    return buffer.str();
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> create_ec_key_from_jwk(const std::string & x_b64, const std::string & y_b64) {
    std::string x_decoded = jwt::base::decode<jwt::alphabet::base64url>(x_b64);
    std::string y_decoded = jwt::base::decode<jwt::alphabet::base64url>(y_b64);

    BIGNUM* x_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(x_decoded.data()), x_decoded.size(), nullptr);
    BIGNUM* y_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(y_decoded.data()), y_decoded.size(), nullptr);

    EC_KEY* raw_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!raw_key) throw std::runtime_error("Failed to create EC_KEY");

    EC_GROUP* group = const_cast<EC_GROUP*>(EC_KEY_get0_group(raw_key));
    EC_POINT* point = EC_POINT_new(group);
    if (!EC_POINT_set_affine_coordinates_GFp(group, point, x_bn, y_bn, nullptr)) {
        throw std::runtime_error("Failed to set affine coordinates");
    }

    EC_KEY_set_public_key(raw_key, point);

    // Cleanup intermediate objects
    EC_POINT_free(point);
    BN_free(x_bn);
    BN_free(y_bn);

    // Return a smart pointer with custom deleter
    return std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>(raw_key, EC_KEY_free);
}

#pragma GCC diagnostic pop

// https://raw.githubusercontent.com/Thalhammer/jwt-cpp/refs/heads/master/example/jwks-verify.cpp

int main(int argc, char *argv[]) {
	std::string pem_priv_key = read_file("testdata/ec256-private.pem");
	std::string pem_pub_key = read_file("testdata/ec256-public.pem");

	std::string issuer = "https://example.com";

	unsigned char nonce[24];
	RAND_bytes(nonce, sizeof(nonce));
	std::string jti = jwt::base::encode<jwt::alphabet::base64url>(std::string{reinterpret_cast<const char*>(nonce), sizeof(nonce)});

	std::string token = jwt::create()
							.set_type("JWT")
							.set_key_id("")
							.set_id(jti)
							.set_issuer(issuer)
							.set_subject("computer.user@example.com")
							.set_issued_at(std::chrono::system_clock::now())
							.set_expires_at(std::chrono::system_clock::now() + std::chrono::hours{24})
							.set_payload_claim("name", jwt::claim(std::string{"Computer User"}))
							.set_payload_claim("website", jwt::claim(std::string{"https://example.com"}))
							.set_payload_claim("email", jwt::claim(std::string{"computer.user@example.com"}))
							.set_payload_claim("scope", jwt::claim(std::string{"openid profile email"}))
							.sign(jwt::algorithm::es256("", pem_priv_key, "", ""));

	auto decoded_jwt = jwt::decode(token);
	fprintf(stdout, "%s\n", token.c_str());
	fprintf(stdout, "%s\n", decoded_jwt.get_payload().c_str());

	std::chrono::seconds secs_since_epoch =  std::chrono::duration_cast<std::chrono::seconds>(decoded_jwt.get_expires_at().time_since_epoch());
	std::cerr << "Expires: " << std::to_string(secs_since_epoch.count()) << "\n";

	auto verifier =
			jwt::verify()
				.allow_algorithm(jwt::algorithm::es256(pem_pub_key, "", "", ""))
				.with_issuer(issuer)
				.with_id(jti)
				.leeway(60UL);

	std::error_code ec;

	verifier.verify(decoded_jwt, ec);

	if (ec) {
		std::cerr << ec.message() << "\n";
	}

	return 0;
}

