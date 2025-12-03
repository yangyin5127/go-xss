package xss_test

import (
	"fmt"
	"strings"

	"github.com/yangyin5127/go-xss"
)

var x *xss.Xss = xss.NewXSS(xss.XssOption{})

func Example() {

	source := "<div a=\"1\" b=\"2\" data-a=\"3\" data-b=\"4\">hello</div>"

	html := xss.FilterXSS(source, xss.XssOption{})
	fmt.Printf("%s\nconvert to:\n%s", source, html)

	//To avoid passing options every time, you can also do it in a faster way by creating a NewXSS instance:

	source = "<div a=\"1\" b=\"2\" data-a=\"3\" data-b=\"4\">hello</div>"

	options := xss.XssOption{}

	x := xss.NewXSS(options)

	html = x.Process(source)
	fmt.Printf("%s\nconvert to:\n%s", source, html)
}

func ExampleNew() {
	source := "<a href=\"javascript:alert(/xss/)\" title=\"hi\">link</a>"
	options := xss.XssOption{}

	x := xss.NewXSS(options)
	safeHtml := x.Process(source)
	fmt.Printf("safeHtml:%s", safeHtml)
}

func ExampleOnIgnoreTagAttr() {
	source := "<div a=\"1\" b=\"2\" data-a=\"3\" data-b=\"4\">hello</div>"

	html := xss.FilterXSS(source, xss.XssOption{
		OnIgnoreTagAttr: func(tag, name, value string, isWhiteAttr bool) *string {
			if len(name) >= 5 && name[0:5] == "data-" {
				ret := name + "=\"" + xss.EscapeAttrValue(value) + "\""
				return &ret
			}
			return nil
		},
	})
	fmt.Printf("%s\nconvert to:\n%s", source, html)
}

func ExampleOnIgnoreTag() {
	source := "<x><x-1>he<x-2 checked></x-2>wwww</x-1><a>"

	html := xss.FilterXSS(source, xss.XssOption{
		OnIgnoreTag: func(tag, html string, options xss.TagOption) *string {
			if len(tag) >= 2 && tag[0:2] == "x-" {
				return &html
			}
			return nil
		},
	})
	fmt.Printf("%s\nconvert to:\n%s", source, html)
}

func ExampleParseHtmlImages() {
	source := "<img src=\"img1\">a<img src=\"img2\">b<img src=\"img3\">c<img src=\"img4\">d"
	var list []string
	xss.FilterXSS(source, xss.XssOption{
		OnTagAttr: func(tag, name, value string, isWhiteAttr bool) *string {
			if tag == "img" && name == "src" {
				list = append(list, value)
			}
			return nil
		},
	})
	fmt.Printf("image list:\n%s", strings.Join(list, ","))
}

func ExampleFilterAllTags() {
	source := "<strong>hello</strong><script>alert(/xss/);</script>end"
	html := xss.FilterXSS(source, xss.XssOption{
		WhiteList:          map[string][]string{}, // 白名单为空，表示过滤所有标签
		StripIgnoreTag:     true,                  // 过滤所有非白名单标签的HTML
		StripIgnoreTagBody: []string{"script"},    //script标签较特殊，需要过滤标签中间的内容
	})
	fmt.Printf("text: %s", html)
}
