package cssfilter

import (
	"strings"
	"unicode"
)

type OnAttrFunc func(sourcePosition int, position int, name string, value string, source string) string

func trimRight(s string) string {
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

func trim(s string) string {
	return strings.TrimSpace(s)
}

func ParseStyle(css string, onAttr OnAttrFunc) string {
	css = trimRight(css)
	if !strings.HasSuffix(css, ";") {
		css += ";"
	}

	cssLen := len(css)
	isParenthesisOpen := false
	lastPos := 0
	i := 0
	retCSS := strings.Builder{}

	addNewAttr := func() {
		if !isParenthesisOpen {
			source := trim(css[lastPos:i])
			j := strings.Index(source, ":")
			if j != -1 {
				name := trim(source[:j])
				value := trim(source[j+1:])
				if name != "" {
					ret := onAttr(lastPos, retCSS.Len(), name, value, source)
					if ret != "" {
						retCSS.WriteString(ret)
						retCSS.WriteString("; ")
					}
				}
			}
		}
		lastPos = i + 1
	}

	for i < cssLen {
		c := css[i]

		// 注释 /* ... */
		if c == '/' && i+1 < cssLen && css[i+1] == '*' {
			j := strings.Index(css[i+2:], "*/")
			if j == -1 {
				break
			}
			i = i + 2 + j + 1
			lastPos = i + 1
			isParenthesisOpen = false
		} else if c == '(' {
			isParenthesisOpen = true
		} else if c == ')' {
			isParenthesisOpen = false
		} else if c == ';' {
			if !isParenthesisOpen {
				addNewAttr()
			}
		} else if c == '\n' {
			addNewAttr()
		}

		i++
	}

	return trim(retCSS.String())
}
