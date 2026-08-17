#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <getopt.h>

#include <fcgiapp.h>
#include "appfileman.hpp"

int sock_fd;

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-U username] [-G group] [-N] <unix_socket_path>\n"
		"\n"
		"Options:\n"
		"  -U username          User to run as\n"
		"  -G group             Group to run as\n"
		"  -N, --no-drop        Do not change socket ownership or drop privileges\n"
		"\n"
		"When -N/--no-drop is supplied, -U and -G are not required and the\n"
		"process continues running with its current user/group privileges.\n"
		"\n"
		"Examples:\n"
		"  %s -U www-data -G www-data /run/fileman_fastcgi.sock\n"
		"  %s -N /run/fileman_fastcgi.sock\n",
		prog,
		prog,
		prog);
}

static volatile sig_atomic_t shutdown_requested = 0;

static void handle_shutdown(int)
{
	shutdown_requested = 1;
	close(sock_fd);
}

static int process_request(FCGX_Request &request)
{
	time_t current_time;
	struct tm *local_time;
	char time_buffer[100];

	current_time = time(NULL);
	local_time = localtime(&current_time);

	strftime(time_buffer,
		 sizeof(time_buffer),
		 "%Y-%m-%dT%H:%M:%S", // %z allowed here for zone
		 local_time);

	FCGX_FPrintF(request.out,
		"Content-Type: text/plain; charset=utf-8\r\n");

	FCGX_FPrintF(request.out, "\r\n");

	FCGX_FPrintF(request.out,
		"Current Date and Time: %s\n",
		time_buffer);

	FCGX_FFlush(request.out);
	FCGX_Finish_r(&request);

	return 0;
}

int main(int argc, char *argv[])
{
	const char *username = NULL;
	const char *groupname = NULL;
	bool drop_privileges = true;

	static const struct option long_options[] = {
		{"no-drop", no_argument, NULL, 'N'},
		{NULL, 0, NULL, 0}
	};

	int opt;

	while ((opt = getopt_long(argc, argv, "U:G:N", long_options, NULL)) != -1) {
		switch (opt) {
		case 'U':
			username = optarg;
			break;

		case 'G':
			groupname = optarg;
			break;

		case 'N':
			drop_privileges = false;
			break;

		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (drop_privileges &&
	    (username == NULL || groupname == NULL)) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	const char *socket_path = argv[optind];

	uid_t target_uid = (uid_t)-1;
	gid_t target_gid = (gid_t)-1;

	/*
	 * We need root privileges in normal mode to:
	 *
	 *   - create/chown the socket
	 *   - switch to the requested user/group
	 *
	 * This works both when invoked directly as root and when the
	 * executable has the setuid-root bit set.
	 *
	 * In --no-drop mode, no privilege changes are performed, so
	 * the process may run as an ordinary user.
	 */
	if (drop_privileges && geteuid() != 0) {
		fprintf(stderr,
			"This program must be run as root or installed SUID root.\n");
		return EXIT_FAILURE;
	}

	/*
	 * Resolve the requested user and group only when privilege
	 * dropping is enabled.
	 */
	if (drop_privileges) {
		struct passwd *pw = getpwnam(username);
		if (pw == NULL) {
			fprintf(stderr, "Unknown user: %s\n", username);
			return EXIT_FAILURE;
		}

		target_uid = pw->pw_uid;

		struct group *gr = getgrnam(groupname);
		if (gr == NULL) {
			fprintf(stderr, "Unknown group: %s\n", groupname);
			return EXIT_FAILURE;
		}

		target_gid = gr->gr_gid;
	}

	if (FCGX_Init() != 0) {
		fprintf(stderr, "Failed to initialize FastCGI library.\n");
		return EXIT_FAILURE;
	}

	sock_fd = FCGX_OpenSocket(socket_path, 32);
	if (sock_fd < 0) {
		perror("Failed to open FastCGI Unix socket");
		return EXIT_FAILURE;
	}

	fprintf(stderr, "FastCGI socket created: %s\n", socket_path);

	if (chmod(socket_path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) != 0) {
		perror("chmod failed");
		return EXIT_FAILURE;
	}

	if (drop_privileges) {
		if (chown(socket_path, target_uid, target_gid) != 0) {
			perror("Failed to change socket ownership");
			close(sock_fd);
			return EXIT_FAILURE;
		}

		if (initgroups(username, target_gid) != 0) {
			perror("Failed to initialize supplementary groups");
			close(sock_fd);
			return EXIT_FAILURE;
		}

		if (setgid(target_gid) != 0) {
			perror("Failed to drop group privileges");
			close(sock_fd);
			return EXIT_FAILURE;
		}

		if (setuid(target_uid) != 0) {
			perror("Failed to drop user privileges");
			close(sock_fd);
			return EXIT_FAILURE;
		}

		if (geteuid() != target_uid || getegid() != target_gid) {
			fprintf(stderr, "Failed to drop privileges correctly.\n");
			close(sock_fd);
			return EXIT_FAILURE;
		}

		fprintf(stderr,
			"Running as user %s (UID %ld), group %s (GID %ld)\n",
			username,
			(long)target_uid,
			groupname,
			(long)target_gid);
	} else {
		fprintf(stderr,
			"Privilege dropping disabled; keeping current user/group "
			"(UID %ld, GID %ld)\n",
			(long)geteuid(),
			(long)getegid());
	}

	fileman_init("data/filemanager.db");

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = handle_shutdown;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) != 0) {
		perror("Failed to install SIGINT handler");
		close(sock_fd);
		return EXIT_FAILURE;
	}

	if (sigaction(SIGTERM, &sa, NULL) != 0) {
		perror("Failed to install SIGTERM handler");
		close(sock_fd);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "FastCGI server listening on Unix socket: %s\n", socket_path);
	fprintf(stderr, "Waiting for connections...\n");

	FCGX_Request request;

	if (FCGX_InitRequest(&request, sock_fd, 0) != 0) {
		fprintf(stderr, "Failed to initialize FastCGI request.\n");
		close(sock_fd);
		return EXIT_FAILURE;
	}

	while (!shutdown_requested) {
		int rc = FCGX_Accept_r(&request);

		if (rc < 0) {
			fprintf(stderr, "FCGX_Accept_r() %d\n", rc);
			break;
		}

		// process_request(request);
		fileman_process_request(&request);
	}

	if (shutdown_requested) {
		fprintf(stderr, "Shutdown Requested\n");
	} else {
		fprintf(stderr, "FCGX_Accept_r failed\n");
	}

	close(sock_fd);

	return EXIT_FAILURE;
}

