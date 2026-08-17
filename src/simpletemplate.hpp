#pragma once

#include <fstream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>

class TemplateEngine
{
public:
	using VariableMap = std::unordered_map<std::string, std::string>;

	TemplateEngine() {
	}

	TemplateEngine(const std::string & filename) {
		LoadFromFile(filename);
	}

	/// Load template from a file.
	bool LoadFromFile(const std::string & filename)
	{
		std::ifstream file(filename);
		if (!file)
			return false;

		std::ostringstream buffer;
		buffer << file.rdbuf();
		m_template = buffer.str();
		m_dirty = true;

		return true;
	}

	/// Set the template directly.
	void SetTemplate(const std::string & text)
	{
		m_template = text;
	}

	/// Get the current template.
	const std::string& GetTemplate() const
	{
		return m_template;
	}

	/// Set a replacement variable.
	TemplateEngine & SetVariable(const std::string & name, const std::string & value)
	{
		m_variables[name] = value;
		m_dirty = true;
		return *this;
	}

	/// Set all variables at once.
	TemplateEngine & SetVariables(const VariableMap & vars)
	{
		m_variables = vars;
		m_dirty = true;
		return *this;
	}

	/// Access variables.
	VariableMap& Variables()
	{
		return m_variables;
	}

	const VariableMap& Variables() const
	{
		return m_variables;
	}

	/// Remove a variable.
	void RemoveVariable(const std::string& name)
	{
		m_variables.erase(name);
		m_dirty = true;
	}

	/// Clear all variables.
	void ClearVariables()
	{
		m_variables.clear();
		m_dirty = true;
	}

	/// Render the template.
	std::string & Render(bool leaveUnknown = true)
	{
		if (!m_dirty) {
			return m_rendered;
		}

		static const std::regex pattern(
			R"(<%\s*([A-Za-z_][A-Za-z0-9_]*)\s*%>)");

		std::string & result = m_rendered;
		std::size_t lastPos = 0;

		auto begin = std::sregex_iterator(m_template.begin(), m_template.end(), pattern);
		auto end = std::sregex_iterator();

		for (auto it = begin; it != end; ++it)
		{
			const auto& match = *it;

			result.append(
				m_template,
				lastPos,
				match.position() - lastPos);

			std::string variable = match[1].str();

			auto replacement = m_variables.find(variable);

			if (replacement != m_variables.end())
			{
				result += replacement->second;
			}
			else if (leaveUnknown)
			{
				result += match.str();
			}

			lastPos = match.position() + match.length();
		}

		result.append(m_template, lastPos);

		m_rendered = result;
		m_dirty = false;

		return result;
	}

private:
	std::string m_template;
	std::string m_rendered;
	VariableMap m_variables;
	bool m_dirty;
};

