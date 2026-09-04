#pragma once

#include <fstream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <optional>

class TemplateEngine
{
public:
	using VariableMap = std::unordered_map<std::string, std::string>;

	TemplateEngine() = default;

	explicit TemplateEngine(std::string templateText)
		: m_template(std::move(templateText))
	{
	}

	/**
	 * Load a template from a file.
	 *
	 * Returns std::nullopt if the file could not be opened.
	 *
	 * Example:
	 *
	 *	 auto page = TemplateEngine::FromFile("page.html");
	 *
	 *	 if (!page)
	 *	 {
	 *		 // Handle error.
	 *	 }
	 */
	static std::optional<TemplateEngine> FromFile(const std::string & filename) {
		std::ifstream file(filename, std::ios::in | std::ios::binary);

		if (!file) {
			return std::nullopt;
		}

		std::ostringstream buffer;
		buffer << file.rdbuf();

		if (file.bad()) {
			return std::nullopt;
		}

		return TemplateEngine(buffer.str());
	}

	TemplateEngine & SetTemplate(std::string text) {
		m_template = std::move(text);
		return *this;
	}

	const std::string & GetTemplate() const {
		return m_template;
	}

	TemplateEngine & SetVariable(std::string name, std::string value) {
		m_variables[std::move(name)] = std::move(value);
		return *this;
	}

	TemplateEngine & SetVariables(const VariableMap& variables) {
		m_variables = variables;
		return *this;
	}

	TemplateEngine & SetVariables(VariableMap&& variables) {
		m_variables = std::move(variables);
		return *this;
	}

	VariableMap & Variables() {
		return m_variables;
	}

	const VariableMap & Variables() const {
		return m_variables;
	}

	TemplateEngine & RemoveVariable(const std::string & name) {
		m_variables.erase(name);
		return *this;
	}

	TemplateEngine & ClearVariables() {
		m_variables.clear();
		return *this;
	}

	/**
	 * Render the template.
	 *
	 * Variables use the following syntax:
	 *
	 *	 <% VARIABLE_NAME %>
	 *
	 * Whitespace around the variable name is allowed:
	 *
	 *	 <%NAME%>
	 *	 <% NAME %>
	 *	 <%   NAME   %>
	 *
	 * If leaveUnknown is true, variables without a corresponding
	 * value are left unchanged.
	 *
	 * If leaveUnknown is false, unknown variables are replaced
	 * with an empty string.
	 */
	std::string Render(bool leaveUnknown = true) const {
		std::string result;

		// This is just a reasonable initial allocation. The rendered
		// output will often be around the same size as the template.
		result.reserve(m_template.size());

		std::size_t position = 0;

		while (position < m_template.size()) {
			const std::size_t start = m_template.find("<%", position);

			// No more template variables.
			if (start == std::string::npos) {
				result.append(m_template, position, std::string::npos);
				break;
			}

			// Copy everything before the variable.
			result.append(m_template, position, start - position);

			const std::size_t end = m_template.find("%>", start + 2);

			// No closing delimiter. Treat the rest as ordinary text.
			if (end == std::string::npos) {
				result.append(m_template, start, std::string::npos);
				break;
			}

			// Extract the contents between <% and %>.
			std::string_view variableName(m_template.data() + start + 2, end - (start + 2));

			variableName = Trim(variableName);

			if (IsValidVariableName(variableName)) {
				const auto it = m_variables.find(std::string(variableName));

				if (it != m_variables.end()) {
					result += it->second;
				} else if (leaveUnknown) {
					// Preserve the original expression exactly.
					result.append(m_template, start, (end + 2) - start);
				}
			} else {
				// Not a valid variable expression. Preserve it.
				result.append(m_template, start, (end + 2) - start);
			}

			position = end + 2;
		}

		return result;
	}

private:
	static bool IsWhitespace(char c) {
		return c == ' ' || c == '\t' || c == '\r' || c == '\n';
	}

	static std::string_view Trim(std::string_view value) {
		std::size_t begin = 0;
		std::size_t end = value.size();

		while (begin < end && IsWhitespace(value[begin])) {
			++begin;
		}

		while (end > begin && IsWhitespace(value[end - 1])) {
			--end;
		}

		return value.substr(begin, end - begin);
	}

	/**
	 * Check whether a string is a valid variable name.
	 *
	 * Valid names are:
	 *
	 *	 VARIABLE
	 *	 VARIABLE_NAME
	 *	 _VARIABLE
	 *	 VARIABLE123
	 *
	 * The first character must be A-Z, a-z or _.
	 * Remaining characters may additionally contain 0-9.
	 */
	static bool IsValidVariableName(std::string_view name) {
		if (name.empty()) {
			return false;
		}

		const char first = name[0];

		if (!((first >= 'A' && first <= 'Z') ||
			  (first >= 'a' && first <= 'z') ||
			  first == '_')) {
			return false;
		}

		for (std::size_t i = 1; i < name.size(); ++i) {
			const char c = name[i];

			if (!((c >= 'A' && c <= 'Z') ||
				  (c >= 'a' && c <= 'z') ||
				  (c >= '0' && c <= '9') ||
				  c == '_')) {
				return false;
			}
		}

		return true;
	}

private:
	std::string m_template;
	VariableMap m_variables;
};

