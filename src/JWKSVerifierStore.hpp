#ifndef JWKS_VERIFIER_STORE_HPP
#define JWKS_VERIFIER_STORE_HPP

#include <iostream>
#include <sstream>
#include <unordered_map>
#include <string>
#include <mutex>
#include <chrono>
#include <stdexcept>
#include <utility>

#include <jwt-cpp/jwt.h>

using json_traits = jwt::traits::kazuho_picojson;

/*
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
*/

/*
 * loaded_from_ contains the URL of the JWKS.
 */

class JWKSStoreManager;

struct JWKSStore {
	using Verifier = jwt::verifier<jwt::default_clock, json_traits>;
	//JWKSStore(const std::string & loaded_from) : loaded_from_{loaded_from}, last_fetch_time_(std::chrono::system_clock::from_time_t(0)), verifiers_{} {}
	//JWKSStore() {}
	/* This function will ignore the issuer (if it exists in each key) and simply add the approprite verifier along with the kid (key id) */
	bool add_key_from_json_object(const picojson::object & key);
	void * add_jwks_verifiers_from_string(const std::string & jwks_string);
	int print_all_keys();
	Verifier * find_verifier(JWKSStoreManager & store_manager, std::string & kid);
	std::string src_url_;
	std::string backing_file_;
	std::chrono::system_clock::time_point last_fetch_time_;
	std::unordered_map<std::string, Verifier> verifiers_;
};

class JWKSStoreManager {
public:
	static size_t curl_write_callback(void * contents, size_t size, size_t nmemb, void * userp);
	std::string fetch_jwks_json(std::string url, time_t * last_write_time);

	static std::string create_pem_ec_key(const std::string & x, const std::string & y, const std::string & d);
	json_traits::object_type get_jwk(const std::string & jwks_url, const std::string & jwks_json, const std::string & key_id);
	JWKSStore * get_or_create_store(const std::string & issuer) {
		JWKSStore * store;
		auto store_it = stores_.find(issuer);
		if (store_it == stores_.end()) {
			auto [it, inserted] = stores_.try_emplace(issuer);
			store = &it->second;
		} else {
			store = &store_it->second;
		}
		return store;
	}
	JWKSStore * add_jwks_verifiers_from_string(const std::string & issuer, const std::string & source_url, const std::string & jwks_json);

//	bool add_verifier_from_json(const std::string & src_url, const std::string & issuer, const picojson::object & key) {
//		//const auto& key = key_val.get<picojson::object>();
//
//		auto kid_it = key.find("kid");
//		auto kty_it = key.find("kty");
//		//auto issuer_it = key.find("issuer");
//
//		if (kid_it == key.end() || !kid_it->second.is<std::string>() ||
//			kty_it == key.end() || !kty_it->second.is<std::string>() /*||
//			issuer_it == key.end() || !issuer_it->second.is<std::string>()*/) {
//			return false;
//		}
//
//		std::string kid = kid_it->second.get<std::string>();
//		std::string kty = kty_it->second.get<std::string>();
//		//std::string issuer = issuer_it->second.get<std::string>();
//		JWKSStore & store = stores_[issuer];
//		//auto store_it = stores_.try_emplace(issuer);
//		store.loaded_from_ = src_url;
//		auto now = std::chrono::system_clock::now();
//		store.last_fetch_time_ = now;
//		return store.add_key_from_json_object(key);
//
//		try {
//			if (kty == "RSA") {
//				std::string n = key.at("n").get<std::string>();
//				std::string e = key.at("e").get<std::string>();
//				//auto rsa_alg = jwt::algorithm::rs256("", "", "", "", n, e);
//				std::string pubkey = jwt::helper::create_public_key_from_rsa_components(n, e);
//				auto rsa_alg = jwt::algorithm::rs256(pubkey);
//				//verifiers_[kid] = Verifier{clock_}.allow_algorithm(rsa_alg);
//				//verifiers_[kid] = Verifier{clock_}.allow_algorithm(rsa_alg);
//				//verifiers_[kid] = jwt::verify<jwt::traits::kazuho_picojson>(clock_).allow_algorithm(rsa_alg);
//				//verifiers_.emplace(kid, jwt::verify<jwt::traits::kazuho_picojson>(clock_).allow_algorithm(rsa_alg));
//				//JWKSStore::Verifier & verifier = add_verifier(src_url, issuer, kid, clock_);
//				//verifier.allow_algorithm(rsa_alg);
//				//verifier.leeway(8UL * 365UL * 24UL * 60UL * 60UL);
//				auto it = stores_.find(issuer);
//				if (it != stores_.end()) {
//					JWKSStore & store = it->second;
//					store.add_key_from_json_object(key);
//				}
//			} else if (kty == "EC") {
//				std::string crv = key.at("crv").get<std::string>();
//				std::string x = key.at("x").get<std::string>();
//				std::string y = key.at("y").get<std::string>();
//
//				if (crv != "P-256") {
//					std::cerr << "Unsupported EC curve: " << crv << "\n";
//					return false;
//				}
//
//				//auto ec_alg = jwt::algorithm::es256("", "", "", "", x, y);
//				std::string pubkey = jwt::helper::create_public_key_from_ec_components(crv, x, y);
//				auto ec_alg = jwt::algorithm::es256(pubkey);
//				//JWKSStore::Verifier & verifier = add_verifier(src_url, issuer, kid, clock_);
//				//verifier.allow_algorithm(ec_alg);
//				//verifier.leeway(8UL * 365UL * 24UL * 60UL * 60UL);
//				//fprintf(stderr, "%s - %s - %s\n", src_url.c_str(), issuer.c_str(), kid.c_str());
//			} else {
//				std::cerr << "Unsupported key type: " << kty << "\n";
//				return false;
//			}
//		} catch (const std::exception & ex) {
//			std::cerr << "Error building verifier for kid " << kid << ": " << ex.what() << "\n";
//			return false;
//		}
//
//		return true;
//	}

//	template <typename... Args>
//	JWKSStore::Verifier & add_verifier(std::string src_url, std::string issuer, std::string kid, Args&&... args)
//	{
//		// Create the store if it does not exist.
//		auto [store_it, store_inserted] = stores_.try_emplace(std::move(issuer));
//		//auto & store = stores_.try_emplace(std::move(issuer)).first->second;
//		auto & store = store_it->second;
//		
//		if (store_inserted) {
//			store.loaded_from_ = std::move(src_url);
//		}
//
//		store.last_fetch_time_ = std::chrono::system_clock::now();
//
//		// Construct Verifier directly inside the unordered_map.
//		// If verifier_name already exists, the arguments are not used.
//		auto [it, inserted] = store.verifiers_.try_emplace(std::move(kid), std::forward<Args>(args)...);
//
//		return it->second;
//	}

	JWKSStore * init_store(const std::string & issuer, const std::string & src_url) {
		auto store_it = stores_.find(issuer);
		if (store_it == stores_.end()) {
			// if the store is not found then we cannot re-fetch because we dont know the issuer's url
			auto [it, inserted] = stores_.try_emplace(issuer);
			it->second.src_url_ = src_url;
			return &it->second;
		}
		return &store_it->second;
	}

	JWKSStore * find_store(const std::string & store_name) {
		auto store_it = stores_.find(store_name);
		if (store_it == stores_.end()) {
			// if the store is not found then we cannot re-fetch because we dont know the issuer's url
			return nullptr;
		}
		return &store_it->second;
	}

	int update_store(JWKSStore & store) {
		if (store.src_url_ == "") {
			fprintf(stderr, "Cannot update store: No src_url_ available\n");
			return -1;
		}
		fprintf(stderr, "Updating Store: %s\n", store.src_url_.c_str());
		{
			std::lock_guard<std::mutex> lock(this->mutex_);
		}
		fprintf(stderr, "Store Update Complete\n");
		return 0;
	}

	JWKSStore::Verifier * get_verifier(std::string issuer, std::string kid) {
		auto store_it = stores_.find(issuer);
		if (store_it == stores_.end()) {
			// if the store is not found then we cannot re-fetch because we dont know the issuer's url
			return nullptr;
		}
		auto & verifiers = store_it->second.verifiers_;
		auto verifier_it = verifiers.find(kid);
		if (verifier_it == verifiers.end()) {
			// if key not found then try and re-fetch the jwks from remote
			return nullptr;
		}
		return &verifier_it->second;
	}

	bool verify_jwt(const std::string & issuer, const std::string & jwt);

private:
	std::mutex mutex_;
	jwt::default_clock clock_;
	std::unordered_map<std::string, JWKSStore> stores_;
};

#endif // JWKS_VERIFIER_STORE_HPP

