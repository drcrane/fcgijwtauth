#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcgiapp.h>

int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <unix_socket_path>\n", argv[0]);
		fprintf(stderr, "Example: %s /tmp/my_fastcgi.sock\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (FCGX_Init() != 0) {
		fprintf(stderr, "Failed to initialize FastCGI library.\n");
		return EXIT_FAILURE;
	}

	int sock_fd = FCGX_OpenSocket(argv[1], 32);
	if (sock_fd < 0) {
		perror("Failed to open FastCGI Unix socket");
		return EXIT_FAILURE;
	}

	fprintf(stderr, "FastCGI server listening on Unix socket: %s\n", argv[1]);
	fprintf(stderr, "Waiting for connections...\n");

	FCGX_Request request;

	// Initialize the request structure for use with the opened socket.
	// The third argument (0) indicates it's a responder application.
	if (FCGX_InitRequest(&request, sock_fd, 0) != 0) {
		fprintf(stderr, "Failed to initialize FastCGI request.\n");
		close(sock_fd);
		return EXIT_FAILURE;
	}

	while (FCGX_Accept_r(&request) >= 0) {
		time_t current_time;
		struct tm *local_time;
		char time_buffer[100];

		current_time = time(NULL);
		local_time = localtime(&current_time);
		strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%dT%H:%M:%S%z", local_time);
		FCGX_FPrintF(request.out, "Content-Type: text/plain; charset=utf-8\r\n");
		FCGX_FPrintF(request.out, "\r\n");
		FCGX_FPrintF(request.out, "Current Date and Time: %s\n", time_buffer);
		FCGX_FFlush(request.out);
		FCGX_Finish_r(&request);
	}
	perror("FCGX_Accept_r failed");
	close(sock_fd);
	return EXIT_FAILURE;
}

