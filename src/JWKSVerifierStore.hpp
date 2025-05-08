#ifndef JWKS_VERIFIER_STORE_HPP
#define JWKS_VERIFIER_STORE_HPP

#include <iostream>
#include <sstream>
#include <unordered_map>
#include <string>
#include <mutex>
#include <chrono>
#include <stdexcept>

#include <jwt-cpp/jwt.h>

using json_traits = jwt::traits::kazuho_picojson;

class JWKSVerifierStore {
public:
	using Verifier = jwt::verifier<jwt::default_clock, json_traits>;

	explicit JWKSVerifierStore(const std::string & jwks_url);

	const Verifier & get_verifier(const std::string & kid);
	static std::string create_pem_ec_key(const std::string & x, const std::string & y, const std::string & d);
	json_traits::object_type get_jwk(const std::string & kid);

private:
	std::string jwks_url_;
	std::string jwks_str_;
	std::unordered_map<std::string, Verifier> verifiers_;
	std::chrono::system_clock::time_point last_fetch_time_;
	std::mutex mutex_;
	jwt::default_clock clock_;

	static size_t curl_write_callback(void * contents, size_t size, size_t nmemb, void * userp);
	std::string fetch_jwks_json(bool force = false);
	void fetch_and_parse_jwks(bool force = false);
};

#endif // JWKS_VERIFIER_STORE_HPP

