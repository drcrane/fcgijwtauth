#ifndef APPAUTH_HPP
#define APPAUTH_HPP

#include <fcgiapp.h>
#include <map>
#include <optional>
#include <vector>
#include "../src/HTTPUtils.hpp"
#include "jwt-cpp/jwt.h"
#include "jwt-cpp/traits/kazuho-picojson/traits.h"
#include "../src/JWKSVerifierStore.hpp"

extern JWKSStoreManager g_store_man;

int appauth_process_request(FCGX_Request * req);

#endif // APPAUTH_HPP

