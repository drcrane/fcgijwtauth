#ifndef APPSPECIFIC_HPP
#define APPSPECIFIC_HPP

#define OAUTH2_DEFAULT_CLIENT_ID ""
#define OAUTH2_DEFAULT_CLIENT_SECRET ""
#define OAUTH2_DEFAULT_REDIRECT_URI ""
#define APPLICATION_WELCOME_TO_COMPANY_NAME ""
#define APPLICATION_APPLICATION_NAME "Portal"
#define APPLICATION_PRIVACY_POLICY_URL ""
#define APPLICATION_APPLICATION_LOGO_LIGHT ""
#define APPLICATION_APPLICATION_LOGO_DARK ""
#define APPLICATION_VERSION_NUMBER "0.0.1"
#define APPLICATION_MAX_POST_SIZE (8 * 1024 * 1024)

//#define APPLICATION_AUTHORISATION_VERIFICATION

//#include "HTTPUtils.hpp"
//#include "jwtinterface.hpp"
//#include "fcgiapp.h"
//int appspecific_authorisation_verification(FCGX_Request * req, HTTPUtils::RequestContext & req_ctx, JWTUserContext & user_ctx);

#define INITDB_STATEMENTS

#endif // APPSPECIFIC_HPP
