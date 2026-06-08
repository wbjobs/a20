package fingerprint

import (
	"regexp"
	"strings"
)

var (
	numberRegex    = regexp.MustCompile(`\b\d+\b`)
	stringRegex    = regexp.MustCompile(`'[^']*'`)
	doubleQuoteRegex = regexp.MustCompile(`"[^"]*"`)
	nullRegex      = regexp.MustCompile(`\bNULL\b`)
	boolRegex      = regexp.MustCompile(`\b(TRUE|FALSE)\b`)
	hexRegex       = regexp.MustCompile(`\b0x[0-9A-Fa-f]+\b`)
	listRegex      = regexp.MustCompile(`\((\s*\?\s*,)+\s*\?\s*\)`)
	wsRegex        = regexp.MustCompile(`\s+`)
)

func Normalize(sql string) string {
	if sql == "" {
		return ""
	}

	sql = stringRegex.ReplaceAllString(sql, "?")
	sql = doubleQuoteRegex.ReplaceAllString(sql, "?")

	sql = hexRegex.ReplaceAllString(sql, "?")

	sql = numberRegex.ReplaceAllString(sql, "?")

	sql = nullRegex.ReplaceAllString(sql, "?")
	sql = boolRegex.ReplaceAllString(sql, "?")

	sql = collapseLists(sql)

	sql = wsRegex.ReplaceAllString(sql, " ")
	sql = strings.TrimSpace(sql)

	return sql
}

func collapseLists(sql string) string {
	return listRegex.ReplaceAllString(sql, "(...)")
}

func Hash(sql string) uint64 {
	normalized := Normalize(sql)
	var h uint64 = 1469598103934665603
	for i := 0; i < len(normalized); i++ {
		h ^= uint64(normalized[i])
		h *= 1099511628211
	}
	return h
}
