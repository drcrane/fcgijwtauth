#include <fcgiapp.h>
#include <memory>
#include <iostream>
#include "querystring.h"
#include "filesystem.h"
#include "dynstring.h"
#include "dynstringprintf.h"
#include "dynstringhtml.h"
#include "strutils.h"
#include "jwtinterface.hpp"
#include "formdecoder.h"
#include "formdecoder_fastcgi.h"
#include "database.h"
#include "HTTPUtils.hpp"
#include "appfileman.hpp"
#include "fileeditor.h"
#include "appspecific.h"

int fileman_process_get_request(FCGX_Request * req, RequestContext & req_ctx);

int fileman_process_index_get_request(FCGX_Request * req, RequestContext & req_ctx);
int fileman_process_index_post_request(FCGX_Request * req, RequestContext & req_ctx);
int fileman_process_list_get_request(FCGX_Request * req, RequestContext & req_ctx);

std::unique_ptr<Database::SQLite3Connection> db_conn = std::unique_ptr<Database::SQLite3Connection>{};

int fileman_init() {
	bool initialise_database = true;
	std::string database_filename = "data/filemanager.db";
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
	req_ctx.document_uri = FCGX_GetParam("DOCUMENT_URI", req->envp);
	req_ctx.query_string = FCGX_GetParam("QUERY_STRING", req->envp);
	req_ctx.request_id = FCGX_GetParam("REQUEST_ID", req->envp);
	req_ctx.cookie = FCGX_GetParam("HTTP_COOKIE", req->envp);
	req_ctx.authorisation = FCGX_GetParam("HTTP_AUTHORIZATION", req->envp);
	req_ctx.remote_addr = FCGX_GetParam("REMOTE_ADDR", req->envp);
	req_ctx.qs = querystring_decode_inplace(req_ctx.query_string);
	try {
		fprintf(stderr, "trying %s for %s\n", req_ctx.request_method, req_ctx.path_info);
		if (strcmp(req_ctx.request_method, "GET") == 0) {
			char const * edit_this_file = querystring_getbykey(req_ctx.qs, "editfile");
			if (edit_this_file != NULL && strcmp(edit_this_file, "true") == 0) {
				fileeditor_renderpage(req, &req_ctx);
			} else {
				fileman_process_get_request(req, req_ctx);
			}
		} else
		if (strcmp(req_ctx.request_method, "POST") == 0) {
			char const * edit_this_file = querystring_getbykey(req_ctx.qs, "editfile");
			if (edit_this_file != NULL && strcmp(edit_this_file, "true") == 0) {
				fileeditor_renderpage(req, &req_ctx);
			}
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

int fileman_file_not_found(FCGX_Request * req, const char * message) {
	const char * out_msg = message ? message : "";
	FCGX_FPrintF(req->out,
			"Status: 404\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"\r\n"
		"<!DOCTYPE html>\r\n"
		"<html>\r\n"
		"<head>\r\n"
		"<meta charset=\"utf-8\">\r\n"
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
		"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
		"<link rel=\"icon\" href=\"data:image/x-icon;base64,AAABAAEAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAEA\">\r\n"
		"</head>\r\n"
		"<body>\r\n"
		"<h1>404 Not Found</h1>\r\n"
		"<p>%s</p>\r\n"
		"</body>\r\n",
		out_msg);

	FCGX_Finish_r(req);
	return 404;
}

int fileman_process_get_request(FCGX_Request * req, RequestContext & req_ctx) {
	DynStringGuard src_dir{};

	src_dir += req_ctx.document_root;
	if (!strutils_ends_with(src_dir.c_str(), "/") && req_ctx.path_info[0] != '/') {
		src_dir += "/";
	}
	src_dir += req_ctx.path_info;

	if (!filesystem_fileexistsex(src_dir.c_str(), FILESYSTEM_ATTR_DIRECTORY)) {
		DynStringGuard message{};
		message += "<p>Could not find <code>";
		dynstringhtml_htmlspecial_encode_appendz(message.ptr(), src_dir.c_str());
		message += "</code>.</p>";
		fprintf(stderr, "FILE (DIR) NOT FOUND: %s\n", src_dir.c_str());
		return fileman_file_not_found(req, message.c_str());
	}
	DynStringGuard page_content{};

	page_content += "Status: 200\r\n"
		"Content-Type: text/html\r\n"
		"\r\n"
		"<!DOCTYPE html>\r\n"
		"<html>\r\n"
		"<head>\r\n"
		"<meta charset=\"utf-8\">\r\n"
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
		"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
		"<link rel=\"icon\" href=\"data:image/x-icon;base64,AAABAAEAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAEA\">\r\n"
		"</head>\r\n"
		"<body>\r\n";

	page_content += "<h1>Index of /";
	dynstringhtml_url_encode_appendz(page_content.ptr(), req_ctx.path_info);
	page_content += "</h1>\r\n"
		"<hr />\r\n";

	std::vector<filesystem_fileitem_ex> file_list;
	filesystemex_list(file_list, src_dir.c_str(), src_dir.c_str(), 0, 1024);

	page_content += "<p>\r\n";
	for (std::vector<struct filesystem_fileitem_ex>::size_type i = 0; i < file_list.size(); ++ i) {
		char const * filename = file_list[i].name.c_str();
		page_content += "<a href=\"";
		dynstringhtml_url_encode_appendz(page_content.ptr(), filename);
		page_content += "\">";
		dynstringhtml_htmlspecial_encode_appendz(page_content.ptr(), filename);
		page_content += "</a><br />\r\n";
	}
	page_content += "</p>\r\n";

	page_content +=
		"<hr />\r\n"
		"<p>portal/" APPLICATION_VERSION_NUMBER " (";
	page_content += req_ctx.remote_addr;
	page_content += ")</p>\r\n"
		"</body>\r\n"
		"</html>\r\n";

	FCGX_PutStr(page_content.c_str(), page_content.length(), req->out);

	FCGX_FFlush(req->out);
	FCGX_FClose(req->out);
	FCGX_Finish_r(req);
	return 0;
}

