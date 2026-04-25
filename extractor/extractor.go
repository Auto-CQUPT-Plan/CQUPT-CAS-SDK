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
