package extractor

import "regexp"

func ExtractInputValue(html []byte, attrs ...string) string {
	htmlStr := string(html)

	inputPattern := `<input[^>]+`
	for _, attr := range attrs {
		inputPattern += `[^>]*` + attr + `[^>]*`
	}
	inputPattern += `[^>]*>`

	re := regexp.MustCompile(`(?i)` + inputPattern)
	match := re.FindString(htmlStr)
	if match == "" {
		return ""
	}

	valueRe := regexp.MustCompile(`(?i)value\s*=\s*["']([^"']*)["']`)
	valueMatch := valueRe.FindStringSubmatch(match)
	if len(valueMatch) > 1 {
		return valueMatch[1]
	}

	return ""
}

// ExtractFormAction 提取指定 id 的 <form> 的 action 属性。找不到返回空字符串。
// 例: ExtractFormAction(html, "pwdFromId") 匹配 <form id="pwdFromId" action="/authserver/login">
func ExtractFormAction(html []byte, formID string) string {
	htmlStr := string(html)

	// 匹配 <form ... id="formID" ...> 或 <form ... id='formID' ...>，允许 id 和 action 不同顺序
	pattern := `(?is)<form[^>]*\bid\s*=\s*["']` + regexp.QuoteMeta(formID) + `["'][^>]*>`
	re := regexp.MustCompile(pattern)
	match := re.FindString(htmlStr)
	if match == "" {
		return ""
	}

	actionRe := regexp.MustCompile(`(?i)\baction\s*=\s*["']([^"']*)["']`)
	actionMatch := actionRe.FindStringSubmatch(match)
	if len(actionMatch) > 1 {
		return actionMatch[1]
	}
	return ""
}

// ExtractAnyFormAction 按顺序尝试多个 form id，返回第一个匹配到的 action。
func ExtractAnyFormAction(html []byte, formIDs ...string) string {
	for _, id := range formIDs {
		if action := ExtractFormAction(html, id); action != "" {
			return action
		}
	}
	return ""
}
