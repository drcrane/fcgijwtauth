#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <malloc.h>
#include <errno.h>

#include <string>
#include <vector>
#include <algorithm>

#include "dynstring.h"
#include "dynstringhtml.h"
#include "dynstringprintf.h"
#include "filesystem.h"
#include "mimedecoder.h"
#include "formdecoder.h"
#include "formdecoder_fastcgi.h"
#include "errorinfo.h"
#include "strutils.h"
#include "fcgiapp.h"
#include "querystring.h"
#include "filesystem.h"

#include "appspecific.h"
#include "fileeditor.h"

int fileeditor_renderpage(FCGX_Request * request, RequestContext * req_ctx) {
	// Render the simple file editor user interface
	// file to edit based on the URL
	dynstring_context_t file_to_edit = DYNSTRING_DEFAULT_INIT;
	dynstring_context_t page_content = DYNSTRING_DEFAULT_INIT;
	const char * createfile = querystring_getbykey(req_ctx->qs, "createfile");
	char * file_data = NULL;
	size_t file_data_size = 0;
	size_t content_length;
	std::string response_header = "Status: 200\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Cache-Control: no-cache\r\n"
		"\r\n";
	int res = 0;
	int rc;
	int slashcount = 0;
	if (req_ctx->document_root[0] == '\0') {
		debug("No DOCUMENT_ROOT specified");
		goto error;
	}
	if (req_ctx->path_info[0] == '\0' || (req_ctx->path_info[0] == '/' && req_ctx->path_info[1] == '\0')) {
		// Cannot edit the directory!
		debug("Cannot edit the directory PATH_INFO: %s", req_ctx->path_info);
		goto finished;
		//goto error;
	}
	if (req_ctx->document_uri[0] == '\0') {
		debug("No DOCUMENT_URI specified");
		goto error;
	}
	if (req_ctx->script_name[0] == '\0') {
		debug("No SCRIPT_NAME specified");
		goto error;
	}
	//debug("document_root %s", req_ctx->document_root);
	//debug("path_info %s", req_ctx->path_info);
	dynstring_appendstringz(&file_to_edit, req_ctx->document_root, NULL);
	if (!dynstring_endswithchar(&file_to_edit, '/') && req_ctx->path_info[0] != '/') {
		dynstring_appendchar(&file_to_edit, '/');
	}
	dynstring_appendstringz(&file_to_edit, req_ctx->path_info, NULL);
	dynstring_appendstringz(&page_content, "<!DOCTYPE html>\r\n"
		"<html>\r\n"
		"<head>\r\n"
		"<meta charset=\"utf-8\">\r\n"
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\r\n"
		"<meta name=\"color-scheme\" content=\"dark light\" />\r\n"
		"<link rel=\"icon\" href=\"data:image/x-icon;base64,AAABAAEAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAEA\">\r\n"
		"<link rel=\"stylesheet\" id=\"default-css\" type=\"text/css\" media=\"all\" href=\"", NULL);
	// find the number of directories we need to navigate back up to get to the base
	slashcount = strutils_countchar(req_ctx->path_info, '/', 0);
	for (int c = 0; c < slashcount; ++c) {
		dynstring_appendstring(&page_content, "../", 3);
	}
	dynstring_appendstringz(&page_content, "fcgijwtauth/htdocs/res/fileeditor_style.css\" />\r\n"
		"</head>\r\n"
		"<body>\r\n", NULL);
	dynstring_appendstringz(&page_content, "<div class=\"container\">\r\n"
		"<header>\r\n"
		"<h1>", req_ctx->path_info, "</h1>\r\n"
		"</header>\r\n", NULL);
	if (createfile != NULL && strcmp(createfile, "true") == 0) {
		if (strcmp(req_ctx->request_method, "POST") == 0) {
			debug("POST Request - ");
			// parse the mime encoded post data
			formdecoder_context * fd_ctx = NULL;
			rc = formdecoder_decodefcgirequest(request, &fd_ctx, APPLICATION_MAX_POST_SIZE, NULL);
			debug("formdecoder_decodefcgirequest() %d", rc);
			if (rc == 0) {
				char * filecontent;
				size_t filecontent_len = 0;
				rc = formdecoder_getfield(fd_ctx, "filecontent", &filecontent_len, &filecontent);
				debug("formdecoder_getfield() %d %d", /* [%s]", */rc, (int)filecontent_len/*, filecontent*/);
				if (filesystem_fileexists(dynstring_getcstring(&file_to_edit))) {
					debug("File already exists, not overwriting it.");
				} else {
					rc = filesystem_saveramtofile(dynstring_getcstring(&file_to_edit), filecontent, filecontent_len);
					debug("filesystem_saveramtofile() %d", rc);
					if (rc == -1) {
						perror("save file didnt work");
					}
					// Redirect to remove the createfile=true and set back to a get request
					response_header = std::string("Status: 303 See Other\r\n"
						"Location: ") + req_ctx->document_uri + "?editfile=true\r\n"
						"Content-Length: 0\r\n"
						"\r\n";
					dynstring_setlength(&page_content, 0);
				}
				formdecoder_dispose(fd_ctx);
				fd_ctx = NULL;
				goto send_headers_and_data_only;
			}
		}
		dynstring_appendstringz(&page_content, "<form method=\"POST\" action=\"",
			req_ctx->document_uri,
			"?editfile=true&createfile=true"
			"\" enctype=\"multipart/form-data\">\r\n"
			"<div class=\"content-area\">\r\n"
			"<textarea id=\"editorTextarea\" name=\"filecontent\">", NULL);
		dynstring_appendstringz(&page_content, "</textarea><br/>\r\n"
			"</div>\r\n"
			"<div class=\"button-container\">\r\n"
			"<div class=\"status-indicator\">\r\n"
			"<span id=\"statusDot\" class=\"status-dot saved\"></span> <span id=\"statusText\">Not modified</span>\r\n"
			"</div>\r\n"
			"<div class=\"file-status-message\" id=\"fileStatusMessage\">A new file will be created</div>\r\n"
			"<button class=\"save\" id=\"saveButton\">Save</button>\r\n"
			"<button class=\"cancel\" id=\"cancelButton\">Cancel</button>\r\n"
			"</div>\r\n"
			"</form>\r\n"
			, NULL);
	} else {
		if (strcmp(req_ctx->request_method, "POST") == 0) {
			// parse the mime encoded post data
			formdecoder_context * fd_ctx = NULL;
			rc = formdecoder_decodefcgirequest(request, &fd_ctx, APPLICATION_MAX_POST_SIZE, NULL);
			debug("formdecoder_decodefcgirequest() %d", rc);
			if (rc == 0) {
				char * filecontent;
				size_t filecontent_len = 0;
				rc = formdecoder_getfield(fd_ctx, "filecontent", &filecontent_len, &filecontent);
				debug("formdecoder_getfield() %d %d", /* [%s]", */rc, (int)filecontent_len/*, filecontent*/);
				rc = filesystem_saveramtofile(dynstring_getcstring(&file_to_edit), filecontent, filecontent_len);
				debug("filesystem_saveramtofile() %d", rc);
				if (rc == -1) {
					perror("save file didnt work");
				}
				formdecoder_dispose(fd_ctx);
				fd_ctx = NULL;
			}
		}
		rc = filesystem_loadfiletoram(dynstring_getcstring(&file_to_edit), (void**)&file_data, &file_data_size);
		if (rc < 0) {
			response_header = "Status: 404\r\n"
				"Content-Type: text-html; charset=utf-8\r\n"
				"Cache-Control: no-cache\r\n"
				"\r\n";
			dynstring_appendstringz(&page_content, "<div class=\"error-content-area\">\r\n"
				"<h1>404 Not Found</h1>\r\n", NULL);
			dynstring_sprintf(&page_content, "<p><code>filesystem_loadfiletoram()</code> returned error code %d (%s)</p>\r\n", errno, strerror(errno));
			dynstring_appendstringz(&page_content, "<p>Attempted to open file: <code>", dynstring_getcstring(&file_to_edit), "</code>.</p>\r\n", NULL);
			res = -1;
			goto controlled_error;
		}
		dynstring_appendstringz(&page_content, "<form method=\"POST\" enctype=\"multipart/form-data\">\r\n"
			"<div class=\"content-area\">\r\n"
			"<textarea id=\"editorTextarea\" name=\"filecontent\">", NULL);
		dynstringhtml_htmlspecial_encode_append(&page_content, file_data, file_data_size);
		dynstring_appendstringz(&page_content, "</textarea><br/>\r\n"
			"</div>\r\n"
			"<div class=\"button-container\">\r\n"
			"<div class=\"status-indicator\">\r\n"
			"<span id=\"statusDot\" class=\"status-dot saved\"></span> <span id=\"statusText\">Not modified</span>\r\n"
			"</div>\r\n"
			"<div class=\"file-status-message\" id=\"fileStatusMessage\">A new file will be created</div>\r\n"
			"<button class=\"save\" id=\"saveButton\">Save</button>\r\n"
			"<button class=\"cancel\" id=\"cancelButton\">Cancel</button>\r\n"
			"</div>\r\n"
			"</form>\r\n"
			, NULL);
	}
	res = 0;
controlled_error:
	dynstring_appendstringz(&page_content, "</div>\r\n", NULL);
	dynstring_appendstringz(&page_content, "<script src=\"", NULL);
	for (int c = 0; c < slashcount; ++c) {
		dynstring_appendstring(&page_content, "../", 3);
	}
	dynstring_appendstringz(&page_content, "fcgijwtauth/htdocs/res/fileeditor_script.js\"></script>\r\n", NULL);
	dynstring_appendstringz(&page_content, R"(<script>
(function() {

const editor = document.getElementById('editorTextarea');
if (editor) {
	editor.addEventListener('keydown', (event) => {
		if (event.key === 'Tab') {
			event.preventDefault();
	
			const focusable = [...document.querySelectorAll(
				'a[href], button:not([disabled]), textarea, input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
			)];
	
			//if (event.ctrlKey) {
			//	const index = focusable.indexOf(editor);
			//	focusable[index + 1]?.focus();
			//	return;
			//}
			if (event.shiftKey) {
				const index = focusable.indexOf(editor);
				focusable[index + 1]?.focus();
				return;
			}
			// Insert a tab character.
			const start = editor.selectionStart;
			const end = editor.selectionEnd;
			editor.value =
				editor.value.substring(0, start) +
				'\t' +
				editor.value.substring(end);
			editor.selectionStart = editor.selectionEnd = start + 1;
		}
	});
}

})();
</script>
)", NULL);
	dynstring_appendstringz(&page_content, "</body>\r\n"
		"</html>\r\n", NULL);
send_headers_and_data_only:
	FCGX_PutStr(response_header.data(), response_header.size(), request->out);
	content_length = dynstring_length(&page_content);
	if (content_length) {
		FCGX_PutStr(page_content.buf, content_length, request->out);
	}
finished:
error:
	dynstring_free(&file_to_edit);
	dynstring_free(&page_content);
	return res;
}

