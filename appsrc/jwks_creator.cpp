#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "picojson/picojson.h"

#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <algorithm>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

EC_KEY* load_ec_private_key(const std::string& filename) {
	FILE* fp = fopen(filename.c_str(), "r");
	if (!fp) throw std::runtime_error("Failed to open PEM file");

	EC_KEY* ec_key = PEM_read_ECPrivateKey(fp, nullptr, nullptr, nullptr);
	fclose(fp);

	if (!ec_key) throw std::runtime_error("Failed to read EC private key");
	return ec_key;
}

std::string base64url_encode(const std::string& input) {
	BIO *bio, *b64;
	BUF_MEM *buffer_ptr;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_write(bio, input.data(), input.size());
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &buffer_ptr);
	std::string encoded(buffer_ptr->data, buffer_ptr->length);
	BIO_free_all(bio);

	// Convert to base64url
	encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());
	std::replace(encoded.begin(), encoded.end(), '+', '-');
	std::replace(encoded.begin(), encoded.end(), '/', '_');

	return encoded;
}

picojson::object ec_to_jwk(EC_KEY* ec_key, bool include_private = false) {
	const EC_GROUP * group = EC_KEY_get0_group(ec_key);
	const EC_POINT * pub_key = EC_KEY_get0_public_key(ec_key);
	const BIGNUM * priv_key = EC_KEY_get0_private_key(ec_key);

	if (!group || !pub_key) {
		throw std::runtime_error("Missing EC key components");
	}

	BIGNUM *x = BN_new(), *y = BN_new();
	if (!EC_POINT_get_affine_coordinates_GFp(group, pub_key, x, y, nullptr)) {
		BN_free(x); BN_free(y);
		throw std::runtime_error("Failed to get EC public key coordinates");
	}

	auto bn_to_base64url = [](const BIGNUM* bn) -> std::string {
		int len = BN_num_bytes(bn);
		std::string bin(len, 0);
		BN_bn2bin(bn, reinterpret_cast<unsigned char*>(&bin[0]));
		return base64url_encode(bin);
	};

	int nid = EC_GROUP_get_curve_name(group);
	std::string crv;
	if (nid == NID_X9_62_prime256v1) crv = "P-256";
	else if (nid == NID_secp384r1) crv = "P-384";
	else if (nid == NID_secp521r1) crv = "P-521";
	else throw std::runtime_error("Unsupported EC curve");

	picojson::object jwk;
	jwk["kty"] = picojson::value("EC");
	jwk["crv"] = picojson::value(crv);
	jwk["x"] = picojson::value(bn_to_base64url(x));
	jwk["y"] = picojson::value(bn_to_base64url(y));

	if (include_private && priv_key) {
		jwk["d"] = picojson::value(bn_to_base64url(priv_key));
	}

	BN_free(x);
	BN_free(y);
	return jwk;
}

int main(int argc, char *argv[]) {
	try {
		EC_KEY* ec_key = load_ec_private_key("testdata/ec256-private.pem");
		picojson::object jwk = ec_to_jwk(ec_key, true);
		EC_KEY_free(ec_key);
		jwk["alg"] = picojson::value("ES256");
		jwk["use"] = picojson::value("sig");
		jwk["kid"] = picojson::value(argv[2]);

		picojson::array keys;
		keys.push_back(picojson::value(jwk));
		picojson::object jwks;
		jwks["issuer"] = picojson::value(argv[1]);
		jwks["keys"] = picojson::value(keys);
		picojson::value jwks_val(jwks);
		std::cout << jwks_val.serialize(true) << std::endl;
	} catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << "\n";
	}

	return 0;
}

#pragma GCC diagnostic pop

