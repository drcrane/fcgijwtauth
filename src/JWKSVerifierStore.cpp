#include "JWKSVerifierStore.hpp"

#include <fstream>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include "filesystem.h"
#include "picojson/picojson.h"
#include "jwt-cpp/jwt.h"

/*
JWKSVerifierStore::JWKSVerifierStore(const std::string& jwks_url)
	: jwks_url_(jwks_url),
	  last_fetch_time_(std::chrono::system_clock::from_time_t(0)) {
	fetch_and_parse_jwks();
}

const JWKSVerifierStore::Verifier& JWKSVerifierStore::get_verifier(const std::string& kid) {
	std::lock_guard<std::mutex> lock(mutex_);

	auto it = verifiers_.find(kid);
	if (it != verifiers_.end()) {
		return it->second;
	}

	if (last_fetch_time_ == std::chrono::system_clock::from_time_t(0)) {
		std::cerr << "[JWKS] No jwks have been fetched yet.\n";
		fetch_and_parse_jwks();
	} else {
		auto now = std::chrono::system_clock::now();
		auto duration_since_fetch = std::chrono::duration_cast<std::chrono::hours>(now - last_fetch_time_);
		if (duration_since_fetch >= std::chrono::hours(24)) {
			std::cerr << "[JWKS] Refreshing JWKS after 24 hours.\n";
			fetch_and_parse_jwks(true);
		} else {
			std::cerr << "[JWKS] Cannot fetch, too soon." << std::chrono::duration_cast<std::chrono::minutes>(duration_since_fetch).count() << " minutes since last fetch\n";
		}
	}

	//it = verifiers_.lower_bound(kid);

	it = verifiers_.find(kid);
	if (it == verifiers_.end()) {
		throw std::runtime_error("KID not found after JWKS reload: " + kid);
	}

	return it->second;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

std::string JWKSVerifierStore::create_pem_ec_key(const std::string & x, const std::string & y, const std::string & d) {
	auto x_bin = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(x));
	auto y_bin = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(y));
	auto d_bin = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(d));

	using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

	BIGNUM_ptr x_bign{BN_bin2bn((const unsigned char *)x_bin.data(), x_bin.size(), NULL), &BN_free};
	BIGNUM_ptr y_bign{BN_bin2bn((const unsigned char *)y_bin.data(), y_bin.size(), NULL), &BN_free};
	BIGNUM_ptr d_bign{BN_bin2bn((const unsigned char *)d_bin.data(), d_bin.size(), NULL), &BN_free};

	std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), &EC_KEY_free);
	if (!ec_key) {
		std::cerr << "Failed to create EC key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		return "";
	}

	std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> pub_key(EC_POINT_new(EC_KEY_get0_group(ec_key.get())), &EC_POINT_free);
	if (!pub_key) {
		std::cerr << "Failed to create EC point: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		return "";
	}

	if (EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ec_key.get()), pub_key.get(),
											 x_bign.get(),
											 y_bign.get(), nullptr) != 1) {
		std::cerr << "Failed to set public key coordinates: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		return "";
	}

	// Set the public key in the EC key
	if (EC_KEY_set_public_key(ec_key.get(), pub_key.get()) != 1) {
		std::cerr << "Failed to set public key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		return "";
	}

	// Set the private key
	if (EC_KEY_set_private_key(ec_key.get(), d_bign.get()) != 1) {
		std::cerr << "Failed to set private key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		return "";
	}

	// Convert the EC key to PEM format
	BIO * bio = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_ECPrivateKey(bio, ec_key.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
		std::cerr << "Failed to write EC key to PEM: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		BIO_free(bio);
		return "";
	}

	BUF_MEM * buf_mem;
	BIO_get_mem_ptr(bio, &buf_mem);
	std::string pem(buf_mem->data, buf_mem->length);

	BIO_free(bio);

	return pem;
}

#pragma GCC diagnostic pop

json_traits::object_type JWKSVerifierStore::get_jwk(const std::string & key_id) {
	std::string jwks_json = fetch_jwks_json();

	picojson::value v;
	std::string err = picojson::parse(v, jwks_json);
	if (!err.empty()) {
		throw std::runtime_error("Failed to parse JWKS: " + err);
	}

	if (!v.is<picojson::object>()) {
		throw std::runtime_error("JWKS is not a JSON object");
	}

	const auto & obj = v.get<picojson::object>();
	auto keys_it = obj.find("keys");
	if (keys_it == obj.end() || !keys_it->second.is<picojson::array>()) {
		throw std::runtime_error("JWKS missing 'keys' array");
	}

	const auto & keys = keys_it->second.get<picojson::array>();

	for (const auto & key_val : keys) {
		if (!key_val.is<picojson::object>()) continue;
		const auto& key = key_val.get<picojson::object>();

		auto kid_it = key.find("kid");
		auto kty_it = key.find("kty");

		if (kid_it == key.end() || !kid_it->second.is<std::string>() ||
			kty_it == key.end() || !kty_it->second.is<std::string>()) {
			continue;
		}

		std::string kid = kid_it->second.get<std::string>();
		std::string kty = kty_it->second.get<std::string>();

		if (kid == key_id) {
			return key_val.get<picojson::object>();
		}
	}
	return json_traits::object_type{};
}

size_t JWKSVerifierStore::curl_write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t total_size = size * nmemb;
	std::string* str = static_cast<std::string*>(userp);
	str->append(static_cast<char*>(contents), total_size);
	return total_size;
}

std::string JWKSVerifierStore::fetch_jwks_json(bool force) {
	if (force == false && !jwks_str_.empty()) {
		return jwks_str_;
	}
	if (jwks_url_.front() == '.' || jwks_url_.front() == '/') {
		std::ifstream file(jwks_url_, std::ios::binary);
		if (!file.is_open()) {
			throw std::runtime_error("Failed to open JWKS file: " + jwks_url_);
		}
		file.seekg(0, std::ios::end);
		std::streamsize size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::string fileContents;
		fileContents.resize(size);

		if (!file.read(fileContents.data(), size)) {
			throw std::runtime_error("Error reading the file: " + jwks_url_);
		}
		return fileContents;
	}
	CURL * curl = curl_easy_init();
	if (!curl) {
		throw std::runtime_error("Failed to initialize cURL");
	}

	std::string response_data;

	curl_easy_setopt(curl, CURLOPT_URL, jwks_url_.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "jwks-verifier/1.0");

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		std::string error_msg = curl_easy_strerror(res);
		curl_easy_cleanup(curl);
		throw std::runtime_error("cURL error: " + error_msg);
	}

	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_cleanup(curl);

	if (http_code != 200) {
		throw std::runtime_error("HTTP error fetching JWKS: " + std::to_string(http_code));
	}

	return response_data;
}

void JWKSVerifierStore::fetch_and_parse_jwks(bool force) {
	std::string jwks_json = fetch_jwks_json(force);

	picojson::value v;
	std::string err = picojson::parse(v, jwks_json);
	if (!err.empty()) {
		throw std::runtime_error("Failed to parse JWKS: " + err);
	}

	if (!v.is<picojson::object>()) {
		throw std::runtime_error("JWKS is not a JSON object");
	}

	const auto & obj = v.get<picojson::object>();
	auto keys_it = obj.find("keys");
	if (keys_it == obj.end() || !keys_it->second.is<picojson::array>()) {
		throw std::runtime_error("JWKS missing 'keys' array");
	}

	const auto & keys = keys_it->second.get<picojson::array>();
	verifiers_.clear();

	for (const auto & key_val : keys) {
		if (!key_val.is<picojson::object>()) continue;
		const auto& key = key_val.get<picojson::object>();

		auto kid_it = key.find("kid");
		auto kty_it = key.find("kty");

		if (kid_it == key.end() || !kid_it->second.is<std::string>() ||
			kty_it == key.end() || !kty_it->second.is<std::string>()) {
			continue;
		}

		std::string kid = kid_it->second.get<std::string>();
		std::string kty = kty_it->second.get<std::string>();

		try {
			if (kty == "RSA") {
				std::string n = key.at("n").get<std::string>();
				std::string e = key.at("e").get<std::string>();
				//auto rsa_alg = jwt::algorithm::rs256("", "", "", "", n, e);
				std::string pubkey = jwt::helper::create_public_key_from_rsa_components(n, e);
				auto rsa_alg = jwt::algorithm::rs256(pubkey);
				//verifiers_[kid] = Verifier{clock_}.allow_algorithm(rsa_alg);
				//verifiers_[kid] = jwt::verify<jwt::traits::kazuho_picojson>(clock_).allow_algorithm(rsa_alg);
				verifiers_.emplace(kid, jwt::verify<jwt::traits::kazuho_picojson>(clock_).allow_algorithm(rsa_alg));

			} else if (kty == "EC") {
				std::string crv = key.at("crv").get<std::string>();
				std::string x = key.at("x").get<std::string>();
				std::string y = key.at("y").get<std::string>();

				if (crv != "P-256") {
					std::cerr << "Unsupported EC curve: " << crv << "\n";
					continue;
				}

				//auto ec_alg = jwt::algorithm::es256("", "", "", "", x, y);
				//std::string pubkey = jwt::algorithm::es256(
				std::string pubkey = jwt::helper::create_public_key_from_ec_components(crv, x, y);
				auto ec_alg = jwt::algorithm::es256(pubkey);
				//verifiers_[kid] = Verifier{clock_}.allow_algorithm(ec_alg);
				//verifiers_[kid] = jwt::verify().allow_algorithm(ec_alg);
				//verifiers_.emplace(kid, jwt::verify<jwt::traits::kazuho_picojson>(clock_).allow_algorithm(ec_alg));
				verifiers_.emplace(kid, Verifier{clock_}.allow_algorithm(ec_alg));

			} else {
				std::cerr << "Unsupported key type: " << kty << "\n";
			}
		} catch (const std::exception& ex) {
			std::cerr << "Error building verifier for kid " << kid << ": " << ex.what() << "\n";
		}
	}

	last_fetch_time_ = std::chrono::system_clock::now();
}
*/

bool JWKSStore::add_key_from_json_object(const picojson::object & key) {
	//const auto& key = key_val.get<picojson::object>();

	auto kid_it = key.find("kid");
	auto kty_it = key.find("kty");
	//auto issuer_it = key.find("issuer");

	if (kid_it == key.end() || !kid_it->second.is<std::string>() ||
		kty_it == key.end() || !kty_it->second.is<std::string>() /*||
		issuer_it == key.end() || !issuer_it->second.is<std::string>()*/) {
		return false;
	}

	std::string kid = kid_it->second.get<std::string>();
	std::string kty = kty_it->second.get<std::string>();

	//std::string issuer = issuer_it->second.get<std::string>();
	try {
		if (kty == "RSA") {
			std::string n = key.at("n").get<std::string>();
			std::string e = key.at("e").get<std::string>();
			//auto rsa_alg = jwt::algorithm::rs256("", "", "", "", n, e);
			std::string pubkey = jwt::helper::create_public_key_from_rsa_components(n, e);
			auto rsa_alg = jwt::algorithm::rs256(pubkey);
			//verifiers_[kid] = Verifier{clock_}.allow_algorithm(rsa_alg);
			//verifiers_[kid] = Verifier{clock_}.allow_algorithm(rsa_alg);
			//verifiers_[kid] = jwt::verify<jwt::traits::kazuho_picojson>(clock_).allow_algorithm(rsa_alg);
			//verifiers_.emplace(kid, jwt::verify<jwt::traits::kazuho_picojson>(clock_).allow_algorithm(rsa_alg));
			//JWKSStore::Verifier & verifier = add_verifier(src_url, issuer, kid, clock_);
			//verifier.allow_algorithm(rsa_alg);
			auto [it, inserted] = this->verifiers_.try_emplace(kid, jwt::default_clock{});
			if (inserted) {
				Verifier & verifier = it->second;
				verifier.allow_algorithm(rsa_alg);
				verifier.leeway(8UL * 365UL * 24UL * 60UL * 60UL);
			} else {
				//fprintf(stderr, "Key already exists? %s\n", kid.c_str());
				return false;
			}
		} else if (kty == "EC") {
			std::string crv = key.at("crv").get<std::string>();
			std::string x = key.at("x").get<std::string>();
			std::string y = key.at("y").get<std::string>();

			if (crv != "P-256") {
				std::cerr << "Unsupported EC curve: " << crv << "\n";
				return false;
			}

			//auto ec_alg = jwt::algorithm::es256("", "", "", "", x, y);
			std::string pubkey = jwt::helper::create_public_key_from_ec_components(crv, x, y);
			auto ec_alg = jwt::algorithm::es256(pubkey);
			//JWKSStore::Verifier & verifier = add_verifier(src_url, issuer, kid, clock_);
			//verifier.allow_algorithm(ec_alg);
			//verifier.leeway(8UL * 365UL * 24UL * 60UL * 60UL);
			//fprintf(stderr, "%s - %s - %s\n", src_url.c_str(), issuer.c_str(), kid.c_str());
			auto [it, inserted] = this->verifiers_.try_emplace(kid, jwt::default_clock{});
			if (inserted) {
				Verifier & verifier = it->second;
				verifier.allow_algorithm(ec_alg);
				verifier.leeway(8UL * 365UL * 24UL * 60UL * 60UL);
			} else {
				//fprintf(stderr, "Key already exists? %s\n", kid.c_str());
				return false;
			}
		} else {
			std::cerr << "Unsupported key type: " << kty << "\n";
			return false;
		}
	} catch (const std::exception & ex) {
		std::cerr << "Error building verifier for kid " << kid << ": " << ex.what() << "\n";
		return false;
	}

	return true;
}

int JWKSStore::print_all_keys() {
	std::cerr << "All keys --------\n";
	for (auto it = this->verifiers_.begin(), it_end = this->verifiers_.end(); it != it_end; ++it) {
		std::cerr << it->first << '\n';
	}
	std::cerr << "-----------------\n";
	return 0;
}

void * JWKSStore::add_jwks_verifiers_from_string(const std::string & jwks_string) {
	json_traits::value_type val;
	json_traits::parse(val, jwks_string);
	int key_count = 0;

	picojson::value & v = val;
	if (!v.is<picojson::object>()) {
		fprintf(stderr, "not an object\n");
		return nullptr;
	}
	v = v.get<picojson::object>().find("keys")->second;
	if (!v.is<picojson::array>()) {
		fprintf(stderr, "not an array\n");
		return nullptr;
	}
	if (v.is<picojson::array>()) {
		const auto & ary = v.get<picojson::array>();
		for (std::size_t idx = 0; idx < ary.size(); ++idx) {
			picojson::object obj = ary[idx].get<picojson::object>();
			add_key_from_json_object(obj);
			//store->add_jwks_verifiers_from_string(const std::string &jwks_string)
			//auto verifier_added = add_verifier_from_json(source_url, issuer, obj);
			//if (verifier_added) {
			//	++key_count;
			//}
		}
	}
	return this;
}

JWKSStore::Verifier * JWKSStore::find_verifier(JWKSStoreManager & store_manager, std::string & kid) {
	auto verifier_it = verifiers_.find(kid);
	JWKSStore::Verifier * verifier = nullptr;
	fprintf(stderr, "JWKSStore::find_verifier(): Finding verifier for %s\n", kid.c_str());
	if (verifier_it == verifiers_.end()) {
		auto now = std::chrono::system_clock::now();
		auto duration_since_fetch = std::chrono::duration_cast<std::chrono::hours>(now - last_fetch_time_);
		if (duration_since_fetch >= std::chrono::hours(24)) {
			std::cerr << "[JWKS] Refreshing JWKS after 24 hours.\n";
			time_t last_write_time = 0L;
			std::string jwks_json_str = store_manager.fetch_jwks_json(src_url_, &last_write_time);
			if (backing_file_ != "") {
				int rc = filesystem_saveramtofile(backing_file_.c_str(), jwks_json_str.data(), jwks_json_str.length());
				if (rc != 0) {
					fprintf(stderr, "JWKSStore::find_verifier(): error saving to backing file: %s\n", backing_file_.c_str());
				}
			} else {
				fprintf(stderr, "Warning: NO BACKING FILE (issuer: %s)\n", "microsoft");
			}
			this->add_jwks_verifiers_from_string(jwks_json_str);
			this->last_fetch_time_ = std::chrono::system_clock::time_point{std::chrono::seconds{last_write_time}};
		} else {
			std::cerr << "[JWKS] Cannot fetch, too soon: " << std::chrono::duration_cast<std::chrono::minutes>(duration_since_fetch).count() << " minutes since last fetch\n";
		}
		verifier_it = verifiers_.find(kid);
	}
	if (verifier_it != verifiers_.end()) {
		return &verifier_it->second;
	}
	return nullptr;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

std::string JWKSStoreManager::create_pem_ec_key(const std::string & x, const std::string & y, const std::string & d) {
	auto x_bin = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(x));
	auto y_bin = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(y));
	auto d_bin = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(d));

	using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

	BIGNUM_ptr x_bign{BN_bin2bn((const unsigned char *)x_bin.data(), x_bin.size(), NULL), &BN_free};
	BIGNUM_ptr y_bign{BN_bin2bn((const unsigned char *)y_bin.data(), y_bin.size(), NULL), &BN_free};
	BIGNUM_ptr d_bign{BN_bin2bn((const unsigned char *)d_bin.data(), d_bin.size(), NULL), &BN_free};

	std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), &EC_KEY_free);
	if (!ec_key) {
		std::cerr << "Failed to create EC key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		return "";
	}

	std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> pub_key(EC_POINT_new(EC_KEY_get0_group(ec_key.get())), &EC_POINT_free);
	if (!pub_key) {
		std::cerr << "Failed to create EC point: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		return "";
	}

	if (EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ec_key.get()), pub_key.get(),
											 x_bign.get(),
											 y_bign.get(), nullptr) != 1) {
		std::cerr << "Failed to set public key coordinates: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		return "";
	}

	// Set the public key in the EC key
	if (EC_KEY_set_public_key(ec_key.get(), pub_key.get()) != 1) {
		std::cerr << "Failed to set public key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		return "";
	}

	// Set the private key
	if (EC_KEY_set_private_key(ec_key.get(), d_bign.get()) != 1) {
		std::cerr << "Failed to set private key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		return "";
	}

	// Convert the EC key to PEM format
	BIO * bio = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_ECPrivateKey(bio, ec_key.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
		std::cerr << "Failed to write EC key to PEM: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		BIO_free(bio);
		return "";
	}

	BUF_MEM * buf_mem;
	BIO_get_mem_ptr(bio, &buf_mem);
	std::string pem(buf_mem->data, buf_mem->length);

	BIO_free(bio);

	return pem;
}

#pragma GCC diagnostic pop

json_traits::object_type JWKSStoreManager::get_jwk(const std::string & jwks_url, const std::string & jwks_json, const std::string & key_id) {
	picojson::value v;
	std::string err = picojson::parse(v, jwks_json);
	if (!err.empty()) {
		throw std::runtime_error("Failed to parse JWKS: " + err);
	}

	if (!v.is<picojson::object>()) {
		throw std::runtime_error("JWKS is not a JSON object");
	}

	const auto & obj = v.get<picojson::object>();
	auto keys_it = obj.find("keys");
	if (keys_it == obj.end() || !keys_it->second.is<picojson::array>()) {
		throw std::runtime_error("JWKS missing 'keys' array");
	}

	const auto & keys = keys_it->second.get<picojson::array>();

	for (const auto & key_val : keys) {
		if (!key_val.is<picojson::object>()) continue;
		const auto& key = key_val.get<picojson::object>();

		auto kid_it = key.find("kid");
		auto kty_it = key.find("kty");

		if (kid_it == key.end() || !kid_it->second.is<std::string>() ||
			kty_it == key.end() || !kty_it->second.is<std::string>()) {
			continue;
		}

		std::string kid = kid_it->second.get<std::string>();
		std::string kty = kty_it->second.get<std::string>();

		if (kid == key_id) {
			return key_val.get<picojson::object>();
		}
	}
	return json_traits::object_type{};
}

size_t JWKSStoreManager::curl_write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t total_size = size * nmemb;
	std::string* str = static_cast<std::string*>(userp);
	str->append(static_cast<char*>(contents), total_size);
	return total_size;
}

std::string JWKSStoreManager::fetch_jwks_json(std::string url, time_t * last_write_time) {
	if (url.front() == '.' || url.front() == '/') {
		std::ifstream file(url, std::ios::binary);
		if (!file.is_open()) {
			throw std::runtime_error("Failed to open JWKS file: " + url);
		}
		file.seekg(0, std::ios::end);
		std::streamsize size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::string fileContents;
		fileContents.resize(size);

		if (!file.read(fileContents.data(), size)) {
			throw std::runtime_error("Error reading the file: " + url);
		}
		//auto last_write_time = std::filesystem::last_write_time(url);
		if (last_write_time) {
			struct stat st;
			if (stat(url.c_str(), &st) == 0) {
				*last_write_time = st.st_mtime;
			}
		}
		return fileContents;
	}
	CURL * curl = curl_easy_init();
	if (!curl) {
		throw std::runtime_error("Failed to initialize cURL");
	}

	std::string response_data;

	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "jwks-verifier/1.0");

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		std::string error_msg = curl_easy_strerror(res);
		curl_easy_cleanup(curl);
		throw std::runtime_error("cURL error: " + error_msg);
	}

	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_cleanup(curl);

	if (http_code != 200) {
		throw std::runtime_error("HTTP error fetching JWKS: " + std::to_string(http_code));
	}

	return response_data;
}

JWKSStore * JWKSStoreManager::add_jwks_verifiers_from_string(const std::string & issuer, const std::string & source_url, const std::string & jwks_json) {
	json_traits::value_type val;
	json_traits::parse(val, jwks_json);
	int key_count = 0;

	picojson::value & v = val;
	if (!v.is<picojson::object>()) {
		fprintf(stderr, "not an object\n");
		return nullptr;
	}
	v = v.get<picojson::object>().find("keys")->second;
	if (!v.is<picojson::array>()) {
		fprintf(stderr, "not an array\n");
		return nullptr;
	}
	JWKSStore * store = find_store(issuer);
	if (store == nullptr) {
		auto [it, inserted] = this->stores_.try_emplace(issuer);
		if (inserted) {
			store = &it->second;
			store->src_url_ = source_url;
			store->last_fetch_time_ = std::chrono::system_clock::now();
		} else {
			return nullptr;
		}
	}
	if (v.is<picojson::array>()) {
		const auto & ary = v.get<picojson::array>();
		for (std::size_t idx = 0; idx < ary.size(); ++idx) {
			picojson::object obj = ary[idx].get<picojson::object>();
			store->add_key_from_json_object(obj);
			//store->add_jwks_verifiers_from_string(const std::string &jwks_string)
			//auto verifier_added = add_verifier_from_json(source_url, issuer, obj);
			//if (verifier_added) {
			//	++key_count;
			//}
		}
	}
	return store;
}

bool JWKSStoreManager::verify_jwt(const std::string & issuer, const std::string & jwt_str) {
	JWKSStore * store = this->find_store(issuer);
	if (store == nullptr) {
		fprintf(stderr, "JWKSStoreManager::verify_jwt(%s): issuer not found\n", issuer.c_str());
		return false;
	}
	jwt::decoded_jwt<jwt::traits::kazuho_picojson> jwt = jwt::decode(jwt_str);
	std::string kid = jwt.get_key_id();
	JWKSStore::Verifier * token_verifier = store->find_verifier(*this, kid);
	if (token_verifier == nullptr) {
		fprintf(stderr, "JWKSStoreManager::verify_jwt(%s): key verifier not found\n", kid.c_str());
		return false;
	}
	try {
		store->print_all_keys();
		token_verifier->verify(jwt);
		return true;
	} catch (std::exception & e) {
		fprintf(stderr, "JWKSStoreManager::verify_jwt(%s): %s", kid.c_str(), e.what());
	}
	return false;
}

