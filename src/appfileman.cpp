#include <fcgiapp.h>
#include <memory>
#include <iostream>
#include "querystring.h"
#include "filesystem.h"
#include "dynstring.h"
#include "dynstringprintf.h"
#include "jwtinterface.hpp"
#include "formdecoder.h"
#include "formdecoder_fastcgi.h"
#include "database.h"
#include "HTTPUtils.hpp"
#include "appfileman.hpp"

int fileman_process_index_get_request(FCGX_Request * req, RequestContext & req_ctx);
int fileman_process_index_post_request(FCGX_Request * req, RequestContext & req_ctx);
int fileman_process_list_get_request(FCGX_Request * req, RequestContext & req_ctx);

std::unique_ptr<Database::SQLite3Connection> db_conn = std::unique_ptr<Database::SQLite3Connection>{};

int fileman_init(char const * database_filename) {
	bool initialise_database = true;
	//std::string database_filename = "data/filemanager.db";
	db_conn = std::make_unique<Database::SQLite3Connection>(database_filename);
	if (initialise_database) {
		Database::SQLite3Statement(db_conn.get(), "DROP TABLE IF EXISTS users;").Execute();
		Database::SQLite3Statement(db_conn.get(), "CREATE TABLE users (username TEXT, groupid INT, PRIMARY KEY (username, groupid));").Execute();
		Database::SQLite3Statement(db_conn.get(), "DROP TABLE IF EXISTS groups;").Execute();
		Database::SQLite3Statement(db_conn.get(), "CREATE TABLE groups (groupid INT, groupname TEXT, PRIMARY KEY (groupid));").Execute();
	}
	return 0;
}

/* this is the main request router */
int fileman_process_request(FCGX_Request * req) {
	RequestContext req_ctx = {};
	req_ctx.request_method = FCGX_GetParam("REQUEST_METHOD", req->envp);
	req_ctx.script_name = FCGX_GetParam("SCRIPT_NAME", req->envp);
	req_ctx.path_info = FCGX_GetParam("PATH_INFO", req->envp);
	req_ctx.document_root = FCGX_GetParam("DOCUMENT_ROOT", req->envp);
	req_ctx.query_string = FCGX_GetParam("QUERY_STRING", req->envp);
	req_ctx.request_id = FCGX_GetParam("REQUEST_ID", req->envp);
	req_ctx.cookie = FCGX_GetParam("HTTP_COOKIE", req->envp);
	req_ctx.authorisation = FCGX_GetParam("HTTP_AUTHORIZATION", req->envp);
	req_ctx.qs = querystring_decode_inplace(req_ctx.query_string);
	try {
		fprintf(stderr, "trying %s for %s\n", req_ctx.request_method, req_ctx.path_info);
		if (strcmp(req_ctx.request_method, "GET") == 0) {
			if (strcmp(req_ctx.path_info, "index") == 0) {
				fileman_process_index_get_request(req, req_ctx);
			} else if (strcmp(req_ctx.path_info, "list") == 0) {
				fileman_process_list_get_request(req, req_ctx);
			}
		} else
		if (strcmp(req_ctx.request_method, "POST") == 0) {
		}
	} catch (std::exception & exc) {
		fprintf(stderr, "Exception: %s\n", exc.what());
		FCGX_FPrintF(req->out,
				"Status: 500\r\n"
				"Content-Type: text/plain; charset=utf-8\r\n"
				"\r\n"
				"500 Internal Server Error\r\n"
				"Please see logs\r\n");
		FCGX_FFlush(req->out);
		FCGX_FClose(req->out);
		FCGX_Finish_r(req);
	}
	return 0;
}

int fileman_process_index_get_request(FCGX_Request * req, RequestContext & req_ctx) {
	//formdecoder_context * fd_ctx = nullptr;
	//formdecoder_decodefcgirequest(req, &fd_ctx, 1024 * 1024, nullptr);
	//formdecoder_context_ptr fd_ctx_ptr = formdecoder_context_ptr(fd_ctx);
	//dynstring_context_t page_content = DYNSTRING_DEFAULT_INIT;
	DynStringGuard page_content{};
	std::string jwt_str = jwtinterface_get_token_from_cookie_or_authorization(req_ctx.cookie, req_ctx.authorisation);
	std::unique_ptr<JWTUserContext> jwt_user_ctx = jwtinterface_getusercontext(jwt_str);
	//std::cerr << jwt_user_ctx->payload_json_str << '\n';
	dynstring_appendstringz(&page_content.get(), "<!DOCTYPE html><html>\r\n<head></head>\r\n<body></body>\r\n</html>\r\n", NULL);
	FCGX_FPrintF(req->out,
			"Status: 200\r\n"
			"Content-Type: text/plain; charset=utf-8\r\n"
			"\r\n"
			"user parsed from jwt ----\r\n"
			"email address: [%s]\r\n"
			"friendly name: %s\r\n",
			/*jwt_user_ctx->payload_json_str.c_str(),*/
			jwt_user_ctx->email_address.c_str(),
			jwt_user_ctx->friendly_name.c_str());

	Database::SQLite3Statement stmt = Database::SQLite3Statement(db_conn.get(), "SELECT groupid FROM users WHERE username = ?;");
	stmt.BindAll(jwt_user_ctx->email_address.c_str());
	FCGX_FPrintF(req->out, "Group membership:\r\n");
	for (Database::Row const & row : stmt) {
		FCGX_FPrintF(req->out, "%d\r\n", row.GetInt64(0));
	}

	FCGX_FFlush(req->out);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

int fileman_process_index_post_request(FCGX_Request * req, RequestContext & req_ctx) {
	formdecoder_context * fd_ctx = nullptr;
	formdecoder_decodefcgirequest(req, &fd_ctx, 1024 * 1024, nullptr);
	formdecoder_context_ptr fd_ctx_ptr = formdecoder_context_ptr(fd_ctx);
	return 0;
}

int fileman_process_list_get_request(FCGX_Request * req, RequestContext & req_ctx) {
	std::string jwt_str = jwtinterface_get_token_from_cookie_or_authorization(req_ctx.cookie, req_ctx.authorisation);
	std::unique_ptr<JWTUserContext> jwt_user_ctx = jwtinterface_getusercontext(jwt_str);
	DynStringGuard http_headers{};
	DynStringGuard page_content{};
	DynStringGuard file_listing_html{};
	std::vector<filesystem_fileitem_ex> file_listing{};
	DynStringGuard file_location{};
	Database::SQLite3Statement stmt = Database::SQLite3Statement(db_conn.get(), "SELECT groupid FROM users WHERE username = ?;");
	stmt.BindAll(jwt_user_ctx->email_address.c_str());
	for (Database::Row const & row : stmt) {
		int64_t client_id = row.GetInt64(0);
		dynstring_setlength(&file_location.get(), 0);
		dynstring_sprintf(&file_location.get(), "data/%d/", client_id);
		fprintf(stderr, "%s\n", file_location.c_str());
		filesystemex_list(file_listing, file_location.c_str(), file_location.c_str(), 1, 64);
		DynStringGuard filename{};
		for (filesystem_fileitem_ex file : file_listing) {
			dynstring_setlength(&filename.get(), 0);
			dynstring_sprintf(&filename.get(), "%d/%s", client_id, file.name.c_str());
			if (file.attrs & FILESYSTEM_ATTR_DIRECTORY) {
				dynstring_appendstringz(&file_listing_html.get(), "DIR ", NULL);
			}
			if (file.attrs & FILESYSTEM_ATTR_SYMBOLICLINK) {
				dynstring_appendstringz(&file_listing_html.get(), "SYM ", NULL);
			}
			dynstring_appendstringz(&file_listing_html.get(), "<a href=\"", filename.c_str(), "\">", filename.c_str(), "</a><br/>\r\n", NULL);
		}
		file_listing.clear();
	}

	dynstring_appendstringz(&http_headers.get(), "Status: 200 OK\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"\r\n",
			NULL);

	FCGX_PutStr(http_headers.c_str(), dynstring_length(&http_headers.get()), req->out);
	FCGX_PutStr(file_listing_html.c_str(), dynstring_length(&file_listing_html.get()), req->out);
	FCGX_FFlush(req->out);
	FCGX_Finish_r(req);

	return 0;
}

