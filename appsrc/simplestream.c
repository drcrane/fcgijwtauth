#include <fcgiapp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define SOCKET_PATH "/var/run/fcgi-jsonp.sock"
#define BUFFER_SIZE 4096
#define OUTPUT_DIR "./requests"

void ensure_output_dir() {
	struct stat st = {0};
	if (stat(OUTPUT_DIR, &st) == -1) {
		mkdir(OUTPUT_DIR, 0700);
	}
}

void generate_filename(char * buffer, size_t size) {
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	
	snprintf(buffer, size, "%s/request_%04d-%02d-%02d_%02d-%02d-%02d.txt",
			 OUTPUT_DIR,
			 tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			 tm->tm_hour, tm->tm_min, tm->tm_sec);
}

int save_request_data(const char *data, size_t length) {
	char filename[256];
	generate_filename(filename, sizeof(filename));
	
	FILE *fp = fopen(filename, "w");
	if (!fp) {
		return -1;
	}
	fwrite(data, 1, length, fp);
	fclose(fp);
	struct stat file_stat;
	if (stat(OUTPUT_DIR, &file_stat) != 0) {
		unlink(filename);
		return -1;
	}
	if (chown(filename, file_stat.st_uid, file_stat.st_gid)) {
		fprintf(stderr, "CHOWN to %i:%i failed\n", file_stat.st_uid, file_stat.st_gid);
	}
	return 0;
}

void process_request(FCGX_Request *request) {
	const char *callback = NULL;
	char *content = NULL;
	int content_length = 0;
	
	char *query_string = FCGX_GetParam("QUERY_STRING", request->envp);
	if (query_string) {
		char * p = strstr(query_string, "callback=");
		if (p) {
			callback = p + 9;
			char *end = strchr(callback, '&');
			if (end) *end = '\0';
		}
		save_request_data(query_string, strlen(query_string));
	}
	
	char *content_length_str = FCGX_GetParam("CONTENT_LENGTH", request->envp);
	if (content_length_str) {
		content_length = atoi(content_length_str);
		if (content_length > 0) {
			content = malloc(content_length + 1);
			if (content) {
				FCGX_GetStr(content, content_length, request->in);
				content[content_length] = '\0';
				save_request_data(content, content_length);
			}
		}
	}
	
	FCGX_FPrintF(request->out, "Status: 200 OK\r\n");
	FCGX_FPrintF(request->out, "Content-Type: application/javascript\r\n");
	FCGX_FPrintF(request->out, "X-Content-Type-Options: nosniff\r\n");
	FCGX_FPrintF(request->out, "X-Accel-Buffering: no\r\n");
	FCGX_FPrintF(request->out, "Cache-Control: no-cache\r\n");
	FCGX_FPrintF(request->out, "\r\n");
	
	if (!callback || *callback == '\0') {
		callback = "callback";
	}

	for (int i = 0; i < 10; i++) {
		FCGX_FPrintF(request->out, "%s({\"count\": %d, \"message\": \"Streaming data %d\"});\n", 
					 callback, i, i);
		FCGX_FFlush(request->out);
		sleep(1);
	}
	
	if (content) {
		free(content);
	}
}

int main() {
	FCGX_Init();
	
	int sock_fd = FCGX_OpenSocket(SOCKET_PATH, 64);
	if (sock_fd < 0) {
		perror("Could not create socket");
		exit(EXIT_FAILURE);
	}
	
	ensure_output_dir();
	
	FCGX_Request request;
	FCGX_InitRequest(&request, sock_fd, 0);
	
	printf("FastCGI JSONP streaming server started on socket %s\n", SOCKET_PATH);
	
	while (FCGX_Accept_r(&request) >= 0) {
		process_request(&request);
		FCGX_Finish_r(&request);
	}
	
	return 0;
}

