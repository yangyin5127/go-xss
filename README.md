[![GoDoc](https://godoc.org/github.com/yangyin5127/go-xss?status.svg)](https://godoc.org/github.com/yangyin5127/go-xss)
[![Go](https://github.com/yangyin5127/go-xss/actions/workflows/go.yml/badge.svg)](https://github.com/yangyin5127/go-xss/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/yangyin5127/go-xss)](https://goreportcard.com/report/github.com/yangyin5127/go-xss)
[![Coverage Status](https://coveralls.io/repos/github/yangyin5127/go-xss/badge.svg?branch=main)](https://coveralls.io/github/yangyin5127/go-xss?branch=main)
[![GitHub license](https://img.shields.io/github/license/yangyin5127/go-xss)](https://github.com/yangyin5127/go-xss/blob/main/LICENSE)

# go-xss 根据白名单过滤 HTML(防止 XSS 攻击)

go-xss is a module used to filter input from users to prevent XSS attacks
 
go-xss是一个用于对用户输入的内容进行过滤，以避免遭受 XSS 攻击的模块（（[什么是 XSS 攻击？](http://baike.baidu.com/view/2161269.htm)）。主要用于论坛、博客、网上商店等等一些可允许用户录入页面排版、格式控制相关的 HTML 的场景，xss模块通过白名单来控制允许的标签及相关的标签属性，另外还提供了一系列的接口以便用户扩展，比其他同类模块更为灵活。


[English](./README.en.md) | 中文文档
 



## 特性

* 白名单控制允许的 HTML 标签及各标签的属性
* 通过自定义处理函数，可对任意标签及其属性进行处理

## 性能

speed: 24MB/s

## 安装

```
go get -u github.com/yangyin5127/go-xss

```
## 使用

```golang

import (
    "github.com/yangyin5127/go-xss"
)


source := "<a href=\"javascript:alert(/xss/)\" title=\"hi\">link</a>"

safeHtml := xss.FilterXSS(source,xss.XssOption{})

```

```golang

import (
    "github.com/yangyin5127/go-xss"
)

source := "<a href=\"javascript:alert(/xss/)\" title=\"hi\">link</a>"
x := xss.NewXSS(xss.XssOption{})
safeHtml := x.Process(source)

```

## 自定义过滤规则（options)

在调用 `xss` 进行过滤时，可通过options参数来设置自定义规则：

```golang
source := "<a href=\"javascript:alert(/xss/)\" title=\"hi\">link</a>"

options := xss.XssOption{}
safeHtml := xss.FilterXSS(source,options)

```

如果不想每次都传入一个 options 参数，可以创建一个 XSS 实例：



```golang
source := "<a href=\"javascript:alert(/xss/)\" title=\"hi\">link</a>"
options := xss.XssOption{}

x := xss.NewXSS(options)
safeHtml := x.Process(source)
```

### 白名单

通过 WhiteList 来指定，格式类型为：`map[string][]string`。不在白名单上的标签将被过滤，不在白名单上的属性也会被过滤。以下是示例：

```golang
// 只允许a标签，该标签只允许href, title, target这三个属性
options.WhiteList = map[string][]string {
		"a":{"href","title","target"},
}
// 使用以上配置后，下面的HTML
// <a href="#" onclick="hello()"><i>大家好</i></a>
// 将被过滤为
// <a href="#">大家好</a>
```
默认白名单参考 `xss.GetDefaultWhiteList()`

### 自定义匹配到标签时的处理方法

通过 `OnTag` 来指定相应的处理函数。以下是详细说明：

```golang
func onTag(tag, html string, options TagOption) *string {
	// tag是当前的标签名称，比如<a>标签，则tag的值是'a'
  // html是该标签的HTML，比如<a>标签，则html的值是'<a>'
  // options是一些附加的信息，具体如下：
  //   isWhite    boolean类型，表示该标签是否在白名单上
  //   isClosing  boolean类型，表示该标签是否为闭合标签，比如</a>时为true
  //   position        integer类型，表示当前标签在输出的结果中的起始位置
  //   sourcePosition  integer类型，表示当前标签在原HTML中的起始位置
  // 如果返回一个字符串，则当前标签将被替换为该字符串
  // 如果返回nil，则使用默认的处理方法：
  //   在白名单上：  通过onTagAttr来过滤属性，详见下文
  //   不在白名单上：通过onIgnoreTag指定，详见下文
}
```

### 自定义匹配到标签的属性时的处理方法

通过 `OnTagAttr` 来指定相应的处理函数。以下是详细说明：

```golang
func OnTagAttr(tag, name, value string,isWhiteAttr bool) *string {
	// tag是当前的标签名称，比如<a>标签，则tag的值是'a'
  // name是当前属性的名称，比如href="#"，则name的值是'href'
  // value是当前属性的值，比如href="#"，则value的值是'#'
  // isWhiteAttr是否为白名单上的属性
  // 如果返回一个字符串，则当前属性值将被替换为该字符串
  // 如果返回nil，则使用默认的处理方法
  //   在白名单上：  调用safeAttrValue来过滤属性值，并输出该属性，详见下文
  //   不在白名单上：通过onIgnoreTagAttr指定，详见下文
}

```


### 自定义匹配到不在白名单上的标签时的处理方法

通过 `OnIgnoreTag` 来指定相应的处理函数。以下是详细说明：

```golang
func OnIgnoreTag(tag, html string, options TagOption) *string {
	// 参数说明与onTag相同
  // 如果返回非nil，则当前标签将被替换为该字符串
  // 如果返回nil，则使用默认的处理方法（通过escape指定，详见下文）
}
```


### 自定义匹配到不在白名单上的属性时的处理方法

通过 `OnIgnoreTagAttr` 来指定相应的处理函数。以下是详细说明：
```golang
func OnIgnoreTagAttr(tag,name, value string,isWhiteAttr bool) *string {
  // 参数说明与onTagAttr相同
  // 如果返回一个字符串，则当前属性值将被替换为该字符串
  // 如果返回nil，则使用默认的处理方法（删除该属）
}
```


### 自定义 HTML 转义函数

通过 `EscapeHtml` 来指定相应的处理函数。以下是默认代码 （不建议修改） ：

```golang
func EscapeHTML(html string) string {
	return regGT.ReplaceAllString(regLT.ReplaceAllString(html,"&lt;"),"&gt;")
}

```

### 自定义标签属性值的转义函数

通过 `SafeAttrValue` 来指定相应的处理函数。以下是详细说明：

```golang
func SafeAttrValue(tag, name, value string) string {
// 参数说明与onTagAttr相同（没有options参数）
  // 返回一个字符串表示该属性值

}
```

### 自定义属性值引用为单引号

当`SingleQuotedAttributeValue`为false时默认为双引号，为true时则为单引号

```golang
options.SingleQuotedAttributeValue = true

// 设置属性为true后，以下HTML
// <a href="#">Hello</a>
// 输出结果:
// <a href='#'>Hello</a>
```


### 自定义 CSS 过滤器

通过 `EnableCssFilter` 来启用 [CSS过滤器](github.com/yangyin5127/go-xss/cssfilter)，启用后会对 style 属性中的内容进行过滤，防止通过 CSS 进行 XSS 攻击


```golang

# 例子
// 允许css filter
options.EnableCssFilter = true
// 开启标签style属性白名单,默认style禁止
options.WhiteList["div"] = []string{"style"}

options.CssFilterOption = xss.NewCssFilterOption()
options.CssFilterOption.WhiteList = ....
// 	OnAttr func(name, value string, options StyleAttrOption) *string
options.CssFilterOption.OnAttr = ....
//  OnIgnoreAttr func(name, value string, options StyleAttrOption) *string
options.CssFilterOption.OnIgnoreAttr = ....


```
more details see: github.com/yangyin5127/go-xss/cssfilter/css_option.go


## 快捷配置

### 去掉不在白名单上的标签

通过 `StripIgnoreTag` 来设置：

* true：去掉不在白名单上的标签
* false：（默认），使用配置的escape函数对该标签进行转义
示例：

当设置 StripIgnoreTag = true时，以下代码

```
code:<script>alert(/xss/);</script>
```
过滤后将输出
```
code:alert(/xss/);
```
### 去掉不在白名单上的标签及标签体


通过 `StripIgnoreTagBody` 来设置：

* `nil`时：（默认），不特殊处理
* `[]string{}`：(空数组) 去掉所有不在白名单上的标签 
* `[]string{"tag1", "tag2"}`：仅去掉指定的不在白名单上的标签

示例：
 
当设置 `StripIgnoreTagBody = []string{"script"}时，以下代码`
```
code:<script>alert(/xss/);</script>
```
过滤后将输出
```
code:

```
## 去掉 HTML 备注

通过 `AllowCommentTag` 来设置：

* true：不处理
* false：（默认），自动去掉 HTML 中的备注
示例：

当设置 `AllowCommentTag = false` 时，以下代码
```
code:<!-- something --> END
```
过滤后将输出
```
code: END
```

## 应用实例


### 允许标签以 data-开头的属性


```golang

	source := "<div a=\"1\" b=\"2\" data-a=\"3\" data-b=\"4\">hello</div>";

	html := xss.FilterXSS(source,xss.XssOption{
			OnIgnoreTagAttr: func(tag,name, value string,isWhiteAttr bool) *string {
				if len(name)>=5 && name[0:5] == "data-" {
					ret := name + "=\"" + xss.EscapeAttrValue(value)+"\""
					return &ret
				}
				return nil
			},
	})
	fmt.Printf("%s\nconvert to:\n%s", source, html);
```

运行结果：

```
<div a="1" b="2" data-a="3" data-b="4">hello</div>
convert to:
<div data-a="3" data-b="4">hello</div>
```

允许名称以 x-开头的标签

```
	source := "<x><x-1>he<x-2 checked></x-2>wwww</x-1><a>";

	html := xss.FilterXSS(source,xss.XssOption{
			OnIgnoreTag: func(tag, html string, options xss.TagOption) *string {
				if len(tag)>=2 && tag[0:2] == "x-" {
					return &html;
				}
				return nil
			},
	})
	fmt.Printf("%s\nconvert to:\n%s", source, html);

```

运行结果

```
<x><x-1>he<x-2 checked></x-2>wwww</x-1><a>
convert to:
&lt;x&gt;<x-1>he<x-2 checked></x-2>wwww</x-1><a>
```

### 分析 HTML 代码中的图片列表

```golang
	source := "<img src=\"img1\">a<img src=\"img2\">b<img src=\"img3\">c<img src=\"img4\">d"
	var list []string
	html := xss.FilterXSS(source,xss.XssOption{
			OnTagAttr: func(tag, name, value string ,isWhiteAttr bool) *string {
				if tag == "img" && name == "src" {
					list = append(list,value)
				}
				return nil
			},
	})
	fmt.Printf("image list:\n%s", strings.Join(list, ","));
```

运行结果：
```golang
image list:
img1, img2, img3, img4
```

### 去除 HTML 标签（只保留文本内容）
```golang
	source := "<strong>hello</strong><script>alert(/xss/);</script>end"
	html := xss.FilterXSS(source,xss.XssOption{
			WhiteList:map[string][]string{},  // // empty, means filter out all tags
			StripIgnoreTag:true, // filter out all HTML not in the whitelist
			StripIgnoreTagBody:[]string{"script"}, // the script tag is a special case, we need
	})
	fmt.Printf("text: %s", html);
```

运行结果：
```
text: helloend

```

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/yangyin5127)


## Inspirations

- https://github.com/leizongmin/js-xss

## License

MIT

