#include "HTTPUtils.hpp"

char const * simple_rest_parsing_test() {
	if (std::optional<HTTPUtils::ParsedPath> parsed_path = HTTPUtils::parse_path("client/8472/job/2026-09-18.0001/list")) {
		if (parsed_path->get_idx(1) != "8472") {
			fprintf(stderr, "unexpected value\n");
		}
	}	
	return NULL;
}

char const * simple_element_parsing_test() {
	char const * path = "client/8472/job/2026-09-18.0002/details";
	if (std::optional<HTTPUtils::ParsedPath> parse_path = HTTPUtils::parse_path(path)) {
		size_t idx = 0;
		if (!HTTPUtils::consume(*parse_path, idx, "client")) {
			return "client not found";
		}
		int client_id;
		if (!HTTPUtils::consume_read(*parse_path, idx, client_id)) {
			return "client_id not parsed";
		}
		if (!HTTPUtils::consume(*parse_path, idx, "job")) {
			return "job not found";
		}
		std::string job_ref;
		if (!HTTPUtils::consume_read(*parse_path, idx, job_ref)) {
			return "job reference not found";
		}
		if (!HTTPUtils::consume(*parse_path, idx, "details")) {
			return "details not found";
		}
		fprintf(stdout, "Client ID %d and Job Reference %s\n", client_id, job_ref.c_str());
	}
	return NULL;
}

int main() {
	char const * res = simple_rest_parsing_test();
	if (res) {
		fprintf(stderr, "%s\n", res);
		return 1;
	}
	res = simple_element_parsing_test();
	if (res) {
		fprintf(stderr, "%s\n", res);
		return 1;
	}
	return 0;
}

