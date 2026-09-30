#ifndef HTTPUTILS_H
#define HTTPUTILS_H

#include <string>
#include <map>
#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <string>
#include <string_view>
#include <charconv>
#include <limits>
#include <stdexcept>
#include <querystring.h>
#include <type_traits>

//std::map<std::string, std::string> parse_cookies(std::string& cookie_header);

// TODO: Implement some kind of RAII thingy like DynStringGuard.

extern "C" {

typedef struct {
	char * name;
	char * value;
} cookie_t;

cookie_t * HTTPUtils_parse_cookies(char * header);
void HTTPUtils_dispose_cookies(cookie_t * cookies);
void HTTPUtils_restore_cookies(char * header, cookie_t * cookies);
char const * HTTPUtils_get_cookie(cookie_t * cookies, char const * name, size_t idx);

};

namespace HTTPUtils {

struct ParsedPath {
	std::string storage;
	/* Ranges are important since the std::string might be re-allocated and lost */
	struct Range { std::size_t offset, length; };
	std::vector<Range> ranges;

	std::string_view get_idx(size_t idx) const {
		if (idx >= ranges.size()) {
			return "";
		}
		Range const & range = ranges.at(idx);
		return std::string_view{storage.data() + range.offset, range.length};
	}

	std::size_t size() const {
		return ranges.size();
	}
};

bool consume(const HTTPUtils::ParsedPath & parsed_path, std::size_t & idx, std::string_view literal);

template<typename T>
bool consume_read_ex(const HTTPUtils::ParsedPath & parsed_path, std::size_t & idx, T & out) {
	if (idx >= parsed_path.size()) {
		return false;
	}
	
	std::string_view segment = parsed_path.get_idx(idx);
	
	// Convert the string view to the target type
	try {
		if constexpr (std::is_integral_v<T>) {
			T value{};
			auto [ptr, ec] = std::from_chars(segment.data(), segment.data() + segment.size(), value);
			if (ec != std::errc{} || ptr != segment.data() + segment.size()) {
				return false;
			}
			out = value;
			//if constexpr (std::is_unsigned_v<T>) {
			//	size_t pos = 0;
			//	unsigned long long value = std::stoull(std::string(segment), &pos);
			//	if (pos != segment.size() || value > static_cast<unsigned long long>(std::numeric_limits<T>::max())) {
			//		return false;
			//	}
			//	out = static_cast<T>(value);
			//} else {
			//	size_t pos = 0;
			//	long long value = std::stoll(std::string(segment), &pos);
			//	if (pos != segment.size() || value < static_cast<long long>(std::numeric_limits<T>::min()) || 
			//		value > static_cast<long long>(std::numeric_limits<T>::max())) {
			//		return false;
			//	}
			//	out = static_cast<T>(value);
			//}
		} else if constexpr (std::is_floating_point_v<T>) {
			size_t pos = 0;
			if constexpr (std::is_same_v<T, float>) {
				out = std::stof(std::string(segment), &pos);
			} else {
				out = std::stod(std::string(segment), &pos);
			}
			if (pos != segment.size()) {
				return false;
			}
		} else if constexpr (std::is_same_v<T, std::string>) {
			out = std::string(segment);
		} else if constexpr (std::is_same_v<T, std::string_view>) {
			out = segment;
		} else {
			return false;
		}
	} catch (const std::exception &) {
		return false;
	}
	
	idx = idx + 1;
	return true;
}

template <class T>
struct PathReader {
	static bool read(std::string_view s, T & out);
};

template <class T, class = void>
struct has_path_reader : std::false_type {};

template <class T>
struct has_path_reader<T, std::void_t<decltype(
	PathReader<T>::read(std::declval<std::string_view>(),
			std::declval<T &>())
)>> : std::true_type {};

template <class T>
inline constexpr bool has_path_reader_v = has_path_reader<T>::value;

template <class T, class = void>
struct is_path_parseable : std::false_type {};

template <class T>
struct is_path_parseable<T, std::void_t<decltype(
	T::parse(std::declval<std::string_view>(), std::declval<T &>())
)>> : std::true_type {};

template <class T>
inline constexpr bool is_path_parseable_v = is_path_parseable<T>::value;

struct ValuationJobReference {
	static bool parse(std::string_view s, ValuationJobReference & out) {
		return true;
	}
};

// user code specializes:
template <> struct PathReader<ValuationJobReference> {
	static bool read(std::string_view s, ValuationJobReference & out) { return ValuationJobReference::parse(s, out); }
};

template<typename T>
bool consume_read(const ParsedPath & p, std::size_t & idx, T & out) {
	if (idx >= p.size()) return false;
	std::string_view seg = p.get_idx(idx);

	if constexpr (std::is_integral_v<T>) {
		auto [ptr, ec] = std::from_chars(seg.data(), seg.data()+seg.size(), out);
		if (ec != std::errc{} || ptr != seg.data()+seg.size()) return false;
	} else if constexpr (std::is_floating_point_v<T>) {
		// from_chars or strtod fallback; range check omitted for brevity
		char buf[64];  // float/double repr fits comfortably
		if (seg.size() >= sizeof buf) return false;
		std::memcpy(buf, seg.data(), seg.size());
		buf[seg.size()] = '\0';
		char * end = nullptr;
		out = static_cast<T>(std::strtod(buf, &end));
		if (end != buf + seg.size()) return false;
	} else if constexpr (std::is_same_v<T, std::string>) {
		out.assign(seg.data(), seg.size());
	} else if constexpr (is_path_parseable_v<T>(out)) {
		//T::read(seg, out);
		return !T::parse(seg, out);
	//} else if constexpr (requires { PathReader<T>::read(seg, out); }) {
	//	if (!PathReader<T>::read(seg, out)) return false;
	//} else {
	//	static_assert(always_false<T>, "no PathReader<T> specialization");
	}

	++idx;
	return true;
}

namespace detail {
inline int hex_val(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

// Appends `src` percent-decoded to `dst`. Returns false on malformed escapes.
inline bool append_percent_decoded(std::string_view src, std::string & dst) {
	for (std::size_t i = 0; i < src.size(); ++i) {
		char c = src[i];
		if (c != '%') { dst.push_back(c); continue; }
		if (i + 2 >= src.size()) return false;
		int hi = hex_val(src[i + 1]);
		int lo = hex_val(src[i + 2]);
		if (hi < 0 || lo < 0) return false;
		dst.push_back(static_cast<char>((hi << 4) | lo));
		i += 2;
	}
	return true;
}
} // namespace detail

std::optional<ParsedPath> parse_path(std::string_view raw);
std::optional<ParsedPath> parse_path(const char * raw);

struct RequestContext {
	std::string request_method;
	std::string request_uri;
	std::string script_name;
	std::string path_info;
	std::string document_root;
	std::string base_loc;
	char * query_string;
	char * request_id;
	char * cookie;
	cookie_t * cookies;
	char * authorisation;
	querystring_context * qs;
	// Disable copy operations to prevent double-free
	RequestContext(const RequestContext &) = delete;
	RequestContext & operator=(const RequestContext &) = delete;
	~RequestContext() {
		querystring_dispose(qs);
		qs = NULL;
		HTTPUtils_dispose_cookies(cookies);
		cookies = NULL;
	}
	HTTPUtils::ParsedPath parsed_path{};
};

} // namespace HTTPUtils

#endif // HTTPUTILS_H

