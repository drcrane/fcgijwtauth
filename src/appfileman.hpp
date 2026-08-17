#ifndef APPFILEMAN_H
#define APPFILEMAN_H

#include <fcgiapp.h>
#include <querystring.h>

struct RequestContext {
	char * request_method;
	char * script_name;
	char * path_info;
	char * document_root;
	char * query_string;
	char * request_id;
	char * cookie;
	char * authorisation;
	querystring_context * qs;
	~RequestContext() {
		querystring_dispose(qs);
	}
	//std::unique_ptr<querystring_context, querystring_dispose> qs;
};

int fileman_init(char const * database_filename);
int fileman_process_request(FCGX_Request * req);

#endif // APPFILEMAN_H
