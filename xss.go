package xss

import (
	// "errors"
	// "bytes"
	"fmt"
	"strings"

	"github.com/yangyin5127/pkg/arrays"
	// "io"
)

type Xss struct {
	options XssOption
}

// NewXSS
func NewXSS(options XssOption) *Xss {

	defaultOption := NewDefaultXssOption()
	if options.OnTag == nil {
		options.OnTag = defaultOption.OnTag
	}

	if options.OnTagAttr == nil {
		options.OnTagAttr = defaultOption.OnTagAttr
	}

	if options.OnIgnoreTag == nil {
		options.OnIgnoreTag = defaultOption.OnIgnoreTag
	}

	if options.OnIgnoreTagAttr == nil {
		options.OnIgnoreTagAttr = defaultOption.OnIgnoreTagAttr
	}

	if options.EscapeHTML == nil {
		options.EscapeHTML = defaultOption.EscapeHTML
	}

	if options.SafeAttrValue == nil {
		options.SafeAttrValue = defaultOption.SafeAttrValue
	}

	if options.WhiteList == nil {
		options.WhiteList = defaultOption.WhiteList
	}

	if options.StripTagBody == nil {
		options.StripTagBody = defaultOption.StripTagBody
	}

	xss := &Xss{
		options: options,
	}
	return xss

}

type AttrResult struct {
	Html    string
	Closing bool
}

// GetAttrs 获取标签属性
func GetAttrs(html string) AttrResult {
	i := spaceIndex(html)
	if i == -1 {
		return AttrResult{
			Html:    "",
			Closing: html[len(html)-2] == '/',
		}
	}
	html = strings.TrimSpace(html[i+1 : len(html)-1])

	var isClosing = false
	if len(html) > 0 {
		isClosing = html[len(html)-1] == '/'
	}

	if isClosing {
		html = strings.TrimSpace(html[0 : len(html)-1])
	}
	return AttrResult{
		Html:    html,
		Closing: isClosing,
	}

}

// Process 处理xss
func (x *Xss) Process(html string) string {

	if len(html) < 3 {
		return html
	}

	//cannot use these two options "stripIgnoreTag" and "onIgnoreTag" at the same time'
	if x.options.StripIgnoreTag {
		x.options.OnIgnoreTag = onIgnoreTagStripAll
	}

	onIgnoreTag := x.options.OnIgnoreTag
	escapeHTML := x.options.EscapeHTML
	onTag := x.options.OnTag
	onTagAttr := x.options.OnTagAttr
	safeAttrValue := x.options.SafeAttrValue
	OnIgnoreTagAttr := x.options.OnIgnoreTagAttr
	whiteList := x.options.WhiteList

	attributeWrapSign := "\""
	if x.options.SingleQuotedAttributeValue {
		attributeWrapSign = "'"
	}

	//remove invisible characters
	if x.options.StripBlankChar {
		html = stripBlankChar(html)
	}

	// remove html comments
	if !x.options.AllowCommentTag {
		html = stripCommentTag(html)
	}

	// if enable stripIgnoreTagBody
	var stripIgnoreTagBody StripTagBodyResult
	if x.options.StripIgnoreTagBody != nil {

		stripIgnoreTagBody = x.options.StripTagBody(x.options.StripIgnoreTagBody, onIgnoreTag)
		onIgnoreTag = stripIgnoreTagBody.OnIgnoreTag
	}

	retHTML := parseTag(html, func(sourcePosition int, position int, tag string, html string, isClosing bool) string {
		isWhite := false

		if _, ok := whiteList[tag]; ok {
			isWhite = true
		}
		info := TagOption{
			SourcePosition: sourcePosition,
			Position:       position,
			IsClosing:      isClosing,
			IsWhite:        isWhite,
		}

		ret := onTag(tag, html, info)

		if ret != nil {
			return *ret
		}

		if info.IsWhite {
			if info.IsClosing {
				return "</" + tag + ">"
			}

			attrs := GetAttrs(html)

			var whiteAttrList []string

			if whiteList, ok := whiteList[tag]; ok {
				whiteAttrList = whiteList
			}

			attrsHTML := parseAttr(attrs.Html, func(name, value string) string {
				isWhiteAttr := arrays.Contains(whiteAttrList, name) != -1

				ret := onTagAttr(tag, name, value, isWhiteAttr)

				if ret != nil {
					return *ret
				}

				if isWhiteAttr {
					value = safeAttrValue(tag, name, value)
					if len(value) > 0 {
						return fmt.Sprintf("%s=%s%s%s", name, attributeWrapSign, value, attributeWrapSign) // name + "=\"" + value + "\""
					} else {
						return name
					}
				} else {
					ret := OnIgnoreTagAttr(tag, name, value, isWhiteAttr)
					if ret != nil {
						return *ret
					}
					return ""

				}
			})

			var html strings.Builder
			// html := "<" + tag
			html.WriteString("<" + tag)
			if len(attrsHTML) > 0 {
				// html += " " + attrsHTML
				html.WriteString(" " + attrsHTML)
			}

			if attrs.Closing {
				// html += " /"
				html.WriteString(" /")
			}

			// html += ">"
			html.WriteString(">")
			return html.String()
		} else {
			ret := onIgnoreTag(tag, html, info)
			if ret != nil {
				return *ret
			}
			return escapeHTML(html)
		}

	}, escapeHTML)

	if x.options.StripIgnoreTagBody != nil {
		retHTML = stripIgnoreTagBody.Remove(retHTML)
	}

	return retHTML
}

// FilterXSS filter xss func
func FilterXSS(html string, options XssOption) string {
	xss := NewXSS(options)
	return xss.Process(html)
}
