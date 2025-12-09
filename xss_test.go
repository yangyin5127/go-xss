package xss

import (
	"testing"

	"github.com/yangyin5127/go-xss/cssfilter"
	// "fmt"
)

func TestProcess_normal(t *testing.T) {

	options := XssOption{
		// StripBlankChar:true,
	}
	xss := NewXSS(options)

	result := xss.Process("")

	if result != "" {
		t.Errorf("empty error %s", result)
	}

	result = xss.Process("123")

	if result != "123" {
		t.Errorf("123 error: %s", result)
	}

	//清除不可见字符

	result = xss.Process("a\u0000\u0001\u0002\u0003\r\n b")

	if result != "a\u0000\u0001\u0002\u0003\r\n b" {
		t.Errorf("invisible characters error %s", result)

	}

	options = XssOption{
		StripBlankChar: true,
	}
	xss = NewXSS(options)
	result = xss.Process("a\u0000\u0001\u0002\u0003\r\n b")

	if result != "a\r\n b" {
		t.Errorf("remove invisible characters error %s", result)

	}

	//过滤不在白名单的标签
	options = XssOption{
		// StripBlankChar:true,
	}
	xss = NewXSS(options)
	result = xss.Process("<b>abcd</b>")

	if result != "<b>abcd</b>" {
		t.Errorf("filter 1 error %s", result)

	}

	result = xss.Process("<o>abcd</o>")

	if result != "&lt;o&gt;abcd&lt;/o&gt;" {
		t.Errorf("filter 2 error %s", result)

	}

	result = xss.Process("<b>abcd</o>")

	if result != "<b>abcd&lt;/o&gt;" {
		t.Errorf("filter 3 error %s", result)

	}

	result = xss.Process("<b><o>abcd</b></o>")

	if result != "<b>&lt;o&gt;abcd</b>&lt;/o&gt;" {
		t.Errorf("filter 4 error %s", result)

	}

	result = xss.Process("<hr>")

	if result != "<hr>" {
		t.Errorf("filter 5 error %s", result)

	}

	result = xss.Process("<xss>")

	if result != "&lt;xss&gt;" {
		t.Errorf("filter 6 error %s", result)

	}

	result = xss.Process("<xss o=\"x\">")

	if result != "&lt;xss o=\"x\"&gt;" {
		t.Errorf("filter 7 error %s", result)

	}

	result = xss.Process("<a><b>c</b></a>")

	if result != "<a><b>c</b></a>" {
		t.Errorf("filter 8 error %s", result)

	}

	result = xss.Process("<a><c>b</c></a>")

	if result != "<a>&lt;c&gt;b&lt;/c&gt;</a>" {
		t.Errorf("filter 8 error %s", result)

	}

	//过滤不是标签的<>

	result = xss.Process("<>>")

	if result != "&lt;&gt;&gt;" {
		t.Errorf("filter invalid tag 1 error %s", result)

	}

	result = xss.Process("<scri" + "pt>")

	if result != "&lt;script&gt;" {
		t.Errorf("filter invalid tag 2 error %s", result)

	}

	result = xss.Process("<<a>b>")

	if result != "&lt;<a>b&gt;" {
		t.Errorf("filter invalid tag 3 error %s", result)

	}

	result = xss.Process("<<<a>>b</a><x>")

	if result != "&lt;&lt;<a>&gt;b</a>&lt;x&gt;" {
		t.Errorf("filter invalid tag 4 error %s", result)

	}

	//过滤不在白名单中的属性

	result = xss.Process("<a oo=\"1\" xx=\"2\" title=\"3\">yy</a>")

	if result != "<a title=\"3\">yy</a>" {
		t.Errorf("filter whitelist  1 error %s", result)

	}

	result = xss.Process("<a title xx oo>pp</a>")

	if result != "<a title>pp</a>" {
		t.Errorf("filter whitelist  2 error %s", result)

	}

	result = xss.Process("<a title \"\">pp</a>")

	if result != "<a title>pp</a>" {
		t.Errorf("filter whitelist  3 error %s", result)

	}

	result = xss.Process("<a t=\"\">")

	if result != "<a>" {
		t.Errorf("filter whitelist  4 error %s", result)

	}

	//属性内的特殊字符
	result = xss.Process("<a title=\"\\'<<>>\">")

	if result != "<a title=\"\\'&lt;&lt;&gt;&gt;\">" {
		t.Errorf("invalid attr value  1 error %s", result)

	}

	result = xss.Process("<a title=\"\"\">")

	if result != "<a title>" {
		t.Errorf("invalid attr value  2 error %s", result)

	}

	result = xss.Process("<a h=title=\"oo\">")

	if result != "<a>" {
		t.Errorf("invalid attr value  3 error %s", result)

	}

	result = xss.Process("<a h= title=\"oo\">")

	if result != "<a>" {
		t.Errorf("invalid attr value  4 error %s", result)

	}

	result = xss.Process("<a title=\"javascript&colonalert(/xss/)\">")

	if result != "<a title=\"javascript:alert(/xss/)\">" {
		t.Errorf("invalid attr value  5 error %s", result)

	}

	result = xss.Process("<a title\"hell aa=\"fdfd title=\"ok\">hello</a>")

	if result != "<a>hello</a>" {
		t.Errorf("invalid attr value  6 error %s", result)

	}

	//自动将属性值的单引号转为双引号
	result = xss.Process("<a title='abcd'>")

	if result != "<a title=\"abcd\">" {
		t.Errorf("attr value quote  1 error %s", result)

	}

	result = xss.Process("<a title='\"'>")

	if result != "<a title=\"&quot;\">" {
		t.Errorf("attr value quote  2 error %s", result)

	}
	// 没有双引号括起来的属性值

	result = xss.Process("<a title=home>")

	if result != "<a title=\"home\">" {
		t.Errorf("attr value quote2  1 error %s", result)

	}

	result = xss.Process("<a title=abc(\"d\")>")

	if result != "<a title=\"abc(&quot;d&quot;)\">" {
		t.Errorf("attr value quote2  2 error %s", result)

	}

	result = xss.Process("<a title=abc('d')>")

	if result != "<a title=\"abc('d')\">" {
		t.Errorf("attr value quote2  3 error %s", result)

	}

	//单个闭合标签
	result = xss.Process("<img src/>")

	if result != "<img src />" {
		t.Errorf("single tag  1 error %s", result)

	}

	result = xss.Process("<img src />")

	if result != "<img src />" {
		t.Errorf("single tag  2 error %s", result)

	}

	result = xss.Process("<img src//>")

	if result != "<img src />" {
		t.Errorf("single tag  3 error %s", result)

	}
	result = xss.Process("<br/>")

	if result != "<br />" {
		t.Errorf("single tag  4 error %s", result)

	}

	result = xss.Process("<br />")

	if result != "<br />" {
		t.Errorf("single tag  5 error %s", result)

	}

	//畸形属性格式
	result = xss.Process("<a target = \"_blank\" title =\"bbb\">")

	if result != "<a target=\"_blank\" title=\"bbb\">" {
		t.Errorf("attr value format 1 error %s", result)

	}

	result = xss.Process("<a target = \"_blank\" title =  title =  \"bbb\">")

	if result != "<a target=\"_blank\" title=\"title\">" {
		t.Errorf("attr value format 2 error %s", result)

	}

	result = xss.Process("<img width = 100    height     =200 title=\"xxx\">")

	if result != "<img width=\"100\" height=\"200\" title=\"xxx\">" {
		t.Errorf("attr value format 3 error %s", result)

	}

	result = xss.Process("<img width = 100    height     =200 title=xxx>")

	if result != "<img width=\"100\" height=\"200\" title=\"xxx\">" {
		t.Errorf("attr value format 4 error %s", result)

	}

	result = xss.Process("<img width = 100    height     =200 title= xxx>")

	if result != "<img width=\"100\" height=\"200\" title=\"xxx\">" {
		t.Errorf("attr value format 5 error %s", result)

	}

	result = xss.Process("<img width = 100    height     =200 title= \"xxx\">")

	if result != "<img width=\"100\" height=\"200\" title=\"xxx\">" {
		t.Errorf("attr value format 6 error %s", result)

	}

	result = xss.Process("<img width = 100    height     =200 title= 'xxx'>")

	if result != "<img width=\"100\" height=\"200\" title=\"xxx\">" {
		t.Errorf("attr value format 7 error %s", result)

	}

	result = xss.Process("<img width = 100    height     =200 title = 'xxx'>")

	if result != "<img width=\"100\" height=\"200\" title=\"xxx\">" {
		t.Errorf("attr value format 8 error %s", result)

	}

	result = xss.Process("<img width = 100    height     =200 title= \"xxx\" no=yes alt=\"yyy\">")

	if result != "<img width=\"100\" height=\"200\" title=\"xxx\" alt=\"yyy\">" {
		t.Errorf("attr value format 9 error %s", result)

	}

	result = xss.Process("<img width = 100    height     =200 title= \"xxx\" no=yes alt=\"'yyy'\">")

	if result != "<img width=\"100\" height=\"200\" title=\"xxx\" alt=\"'yyy'\">" {
		t.Errorf("attr value format 10 error %s", result)

	}

	// 使用Tab或换行符分隔的属性

	result = xss.Process("<img width=100 height=200\nsrc=\"#\"/>")

	if result != "<img width=\"100\" height=\"200\" src=\"#\" />" {
		t.Errorf("tab format 1 error %s", result)

	}

	result = xss.Process("<a\ttarget=\"_blank\"\ntitle=\"bbb\">")

	if result != "<a target=\"_blank\" title=\"bbb\">" {
		t.Errorf("tab format 2 error %s", result)

	}

	result = xss.Process("<a\ntarget=\"_blank\"\ttitle=\"bbb\">")

	if result != "<a target=\"_blank\" title=\"bbb\">" {
		t.Errorf("tab format 3 error %s", result)

	}

	result = xss.Process("<a\n\n\n\ttarget=\"_blank\"\t\t\t\ntitle=\"bbb\">")

	if result != "<a target=\"_blank\" title=\"bbb\">" {
		t.Errorf("tab format 4 error %s", result)

	}
}

func TestProcess_WhiteList(t *testing.T) {
	options := XssOption{
		// StripBlankChar:true,
		WhiteList: make(map[string][]string),
	}
	xss := NewXSS(options)

	result := xss.Process("<a title=\"xx\">bb</a>")

	if result != "&lt;a title=\"xx\"&gt;bb&lt;/a&gt;" {
		t.Errorf("WhiteList 1 error %s", result)

	}

	result = xss.Process("<hr>")

	if result != "&lt;hr&gt;" {
		t.Errorf("WhiteList 2 error %s", result)

	}

	options.WhiteList = map[string][]string{
		"ooxx": {"yy"},
	}
	xss = NewXSS(options)

	result = xss.Process("<ooxx yy=\"ok\" cc=\"no\">uu</ooxx>")

	if result != "<ooxx yy=\"ok\">uu</ooxx>" {
		t.Errorf("WhiteList 3 error %s", result)

	}

}

func TestProcess_Evasion_Cheat_Sheet(t *testing.T) {
	options := XssOption{}
	xss := NewXSS(options)

	result := xss.Process("></SCRI" +
		"PT>\">'><SCRI" +
		"PT>alert(String.fromCharCode(88,83,83))</SCRI" +
		"PT>")

	if result != "&gt;&lt;/SCRIPT&gt;\"&gt;'&gt;&lt;SCRIPT&gt;alert(String.fromCharCode(88,83,83))&lt;/SCRIPT&gt;" {
		t.Errorf("Evasion_Cheat_Sheet 1 error %s", result)

	}

	result = xss.Process(";!--\"<XSS>=&{()}")

	if result != ";!--\"&lt;XSS&gt;=&{()}" {
		t.Errorf("Evasion_Cheat_Sheet 2 error %s", result)

	}

	result = xss.Process("<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRI" + "PT>")

	if result != "&lt;SCRIPT SRC=http://ha.ckers.org/xss.js&gt;&lt;/SCRIPT&gt;" {
		t.Errorf("Evasion_Cheat_Sheet 3 error %s", result)

	}

	result = xss.Process("<IMG SRC=\"javascript:alert('XSS');\">")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 4 error %s", result)

	}

	result = xss.Process("<IMG SRC=javascript:alert('XSS')>")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 4 error %s", result)

	}

	result = xss.Process("<IMG SRC=JaVaScRiPt:alert('XSS')>")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 5 error %s", result)

	}
	result = xss.Process("<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 6 error %s", result)

	}

	result = xss.Process("<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">")

	if result != "<img>&lt;SCRIPT&gt;alert(\"XSS\")&lt;/SCRIPT&gt;\"&gt;" {
		t.Errorf("Evasion_Cheat_Sheet 7 error %s", result)

	}

	result = xss.Process("<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 8 error %s", result)

	}

	result = xss.Process("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 9 error %s", result)

	}

	result = xss.Process("<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 10 error %s", result)

	}

	result = xss.Process("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 11 error %s", result)

	}

	result = xss.Process("<IMG SRC=\"jav ascript:alert('XSS');\">")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 12 error %s", result)

	}

	result = xss.Process("<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 13 error %s", result)

	}

	result = xss.Process("<IMG SRC=\"jav\nascript:alert('XSS');\">")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 14 error %s", result)

	}

	result = xss.Process("<IMG SRC=java\\0script:alert(\"XSS\")>")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 15 error %s", result)

	}

	result = xss.Process("<IMG SRC=\" &#14;  javascript:alert('XSS');\">")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 16 error %s", result)

	}

	result = xss.Process("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>")

	if result != "&lt;SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"&gt;&lt;/SCRIPT&gt;" {
		t.Errorf("Evasion_Cheat_Sheet 17 error %s", result)

	}

	result = xss.Process("<BODY onload!#$%&()*~+-_.,:;?@[/|]^`=alert(\"XSS\")>")

	if result != "&lt;BODY onload!#$%&()*~+-_.,:;?@[/|]^`=alert(\"XSS\")&gt;" {
		t.Errorf("Evasion_Cheat_Sheet 18 error %s", result)

	}

	result = xss.Process("<<SCRIPT>alert(\"XSS\");//<</SCRIPT>")

	if result != "&lt;&lt;SCRIPT&gt;alert(\"XSS\");//&lt;&lt;/SCRIPT&gt;" {
		t.Errorf("Evasion_Cheat_Sheet 19 error %s", result)

	}

	result = xss.Process("<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >")

	if result != "&lt;SCRIPT SRC=http://ha.ckers.org/xss.js?&lt; B &gt;" {
		t.Errorf("Evasion_Cheat_Sheet 20 error %s", result)

	}

	result = xss.Process("<SCRIPT SRC=//ha.ckers.org/.j")

	if result != "&lt;SCRIPT SRC=//ha.ckers.org/.j" {
		t.Errorf("Evasion_Cheat_Sheet 21 error %s", result)

	}

	result = xss.Process("<ſcript src=\"https://xss.haozi.me/j.js\"></ſcript>")

	if result != "&lt;ſcript src=\"https://xss.haozi.me/j.js\"&gt;&lt;/ſcript&gt;" {
		t.Errorf("Evasion_Cheat_Sheet 22 error %s", result)

	}

	result = xss.Process("<IMG SRC=\"javascript:alert('XSS')\"")

	if result != "&lt;IMG SRC=\"javascript:alert('XSS')\"" {
		t.Errorf("Evasion_Cheat_Sheet 23 error %s", result)

	}

	result = xss.Process("<iframe src=http://ha.ckers.org/scriptlet.html <")

	if result != "&lt;iframe src=http://ha.ckers.org/scriptlet.html &lt;" {
		t.Errorf("Evasion_Cheat_Sheet 24 error %s", result)

	}

	options.WhiteList = map[string][]string{
		"a": {"style"},
	}
	xss = NewXSS(options)

	result = xss.Process("<a style=\"url('javascript:alert(1)')\">")

	if result != "<a style>" {
		t.Errorf("Evasion_Cheat_Sheet 25 error %s", result)

	}

	options.WhiteList = map[string][]string{
		"td": {"background"},
	}
	xss = NewXSS(options)

	result = xss.Process("<td background=\"url('javascript:alert(1)')\">")

	if result != "<td background>" {
		t.Errorf("Evasion_Cheat_Sheet 26 error %s", result)

	}

	options.WhiteList = map[string][]string{
		"div": {"style"},
	}
	xss = NewXSS(options)

	result = xss.Process("<DIV STYLE=\"width: \nexpression(alert(1));\">")

	if result != "<div style>" {
		t.Errorf("Evasion_Cheat_Sheet 27 error %s", result)

	}

	result = xss.Process("<DIV STYLE=\"background:\n url (javascript:ooxx);\">")

	if result != "<div style>" {
		t.Errorf("Evasion_Cheat_Sheet 28 error %s", result)

	}

	result = xss.Process("<DIV STYLE=\"background:url (javascript:ooxx);\">")

	if result != "<div style>" {
		t.Errorf("Evasion_Cheat_Sheet 29 error %s", result)

	}

	result = xss.Process("<DIV STYLE=\"background: url (ooxx);\">")

	if result != "<div style=\"background: url (ooxx);\">" {
		t.Errorf("Evasion_Cheat_Sheet 30 error %s", result)

	}

	options.WhiteList = nil
	xss = NewXSS(options)
	result = xss.Process("<IMG SRC='vbscript:msgbox(\"XSS\")'>")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 31 error %s", result)

	}

	result = xss.Process("<IMG SRC=\"livescript:[code]\">")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 32 error %s", result)

	}

	result = xss.Process("<IMG SRC=\"mocha:[code]\">")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 33 error %s", result)

	}

	result = xss.Process("<a href=\"javas/**/cript:alert('XSS');\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 34 error %s", result)

	}

	result = xss.Process("<a href=\"javascript\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 35 error %s", result)

	}

	result = xss.Process("<a href=\"/javascript/a\">")

	if result != "<a href=\"/javascript/a\">" {
		t.Errorf("Evasion_Cheat_Sheet 36 error %s", result)

	}

	result = xss.Process("<a href=\"/javascript/a\">")

	if result != "<a href=\"/javascript/a\">" {
		t.Errorf("Evasion_Cheat_Sheet 37 error %s", result)

	}

	result = xss.Process("<a href=\"http://aa.com\">")

	if result != "<a href=\"http://aa.com\">" {
		t.Errorf("Evasion_Cheat_Sheet 38 error %s", result)

	}

	result = xss.Process("<a href=\"https://aa.com\">")

	if result != "<a href=\"https://aa.com\">" {
		t.Errorf("Evasion_Cheat_Sheet 39 error %s", result)

	}

	result = xss.Process("<a href=\"mailto:me@ucdok.com\">")

	if result != "<a href=\"mailto:me@ucdok.com\">" {
		t.Errorf("Evasion_Cheat_Sheet 40 error %s", result)

	}

	result = xss.Process("<a href=\"tel:0123456789\">")

	if result != "<a href=\"tel:0123456789\">" {
		t.Errorf("Evasion_Cheat_Sheet 41 error %s", result)

	}

	result = xss.Process("<a href=\"#hello\">")

	if result != "<a href=\"#hello\">" {
		t.Errorf("Evasion_Cheat_Sheet 42 error %s", result)

	}

	result = xss.Process("<a href=\"other\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 43 error %s", result)

	}

	options.AllowCommentTag = true
	xss = NewXSS(options)

	result = xss.Process("<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]--> END")

	if result != "&lt;!--[if gte IE 4]&gt;&lt;SCRIPT&gt;alert('XSS');&lt;/SCRIPT&gt;&lt;![endif]--&gt; END" {
		t.Errorf("Evasion_Cheat_Sheet 44 error %s", result)

	}

	options.AllowCommentTag = false
	xss = NewXSS(options)
	result = xss.Process("<!--[if gte IE 4]><SCRI" +
		"PT>alert('XSS');</SCRI" +
		"PT><![endif]--> END")

	if result != " END" {
		t.Errorf("Evasion_Cheat_Sheet 45 error %s", result)

	}

	result = xss.Process("<a href=\"javascript&colon;alert(/xss/)\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 46 error %s", result)

	}

	result = xss.Process("<a href=\"javascript&colonalert(/xss/)\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 47 error %s", result)

	}

	result = xss.Process("<a href=\"a&NewLine;b\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 48 error %s", result)

	}

	result = xss.Process("<a href=\"a&NewLineb\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 49 error %s", result)

	}

	result = xss.Process("<a href=\"javasc&NewLine;ript&colon;alert(1)\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 50 error %s", result)

	}

	// data URI 协议过滤
	result = xss.Process("<a href=\"data:\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 51 error %s", result)

	}
	result = xss.Process("<a href=\"d a t a : \">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 52 error %s", result)

	}

	result = xss.Process("<a href=\"data: html/text;\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 53 error %s", result)

	}

	result = xss.Process("<a href=\"data:html/text;\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 54 error %s", result)

	}

	result = xss.Process("<a href=\"data:html /text;\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 55 error %s", result)

	}

	result = xss.Process("<a href=\"data: image/text;\">")

	if result != "<a href>" {
		t.Errorf("Evasion_Cheat_Sheet 56 error %s", result)

	}

	result = xss.Process("<img src=\"data: aaa/text;\">")

	if result != "<img src>" {
		t.Errorf("Evasion_Cheat_Sheet 57 error %s", result)

	}

	result = xss.Process("<img src=\"data:image/png; base64; ofdkofiodiofl\">")

	if result != "<img src=\"data:image/png; base64; ofdkofiodiofl\">" {
		t.Errorf("Evasion_Cheat_Sheet 58 error %s", result)

	}

	options.AllowCommentTag = false
	xss = NewXSS(options)
	result = xss.Process("<!--                               -->")

	if result != "" {
		t.Errorf("Evasion_Cheat_Sheet 59 error %s", result)

	}

	result = xss.Process("<!--              a                 -->")

	if result != "" {
		t.Errorf("Evasion_Cheat_Sheet 60 error %s", result)

	}

	result = xss.Process("<!--sa       -->ss")

	if result != "ss" {
		t.Errorf("Evasion_Cheat_Sheet 62 error %s", result)

	}

	result = xss.Process("<!--                               ")

	if result != "&lt;!--                               " {
		t.Errorf("Evasion_Cheat_Sheet 62 error %s", result)

	}

}

func TestFilterXSS(t *testing.T) {

	result := FilterXSS("<!--[if gte IE 4]><SCRI"+
		"PT>alert('XSS');</SCRI"+
		"PT><![endif]--> END", XssOption{})

	if result != " END" {
		t.Errorf("TestFilterXSS  error %s", result)

	}
}

func TestOnTagCustomMethod(t *testing.T) {
	source := "dd<a href=\"#\"><b><c>haha</c></b></a><br>ff"

	i := 0
	html := FilterXSS(source, XssOption{
		OnTag: func(tag, html string, options TagOption) *string {
			i++

			if i == 1 {
				if tag != "a" {
					t.Errorf("invalid tag")
				}
				if html != "<a href=\"#\">" {
					t.Errorf("invalid tag html")
				}
				if options.IsClosing != false {
					t.Errorf("invalid tag isClosing")
				}
				if options.Position != 2 {
					t.Errorf("invalid tag Position")
				}
				if options.SourcePosition != 2 {
					t.Errorf("invalid tag sourcePosition")
				}

				if options.IsWhite != true {
					t.Errorf("invalid tag IsWhite")
				}

			}

			if i == 2 {
				if tag != "b" {
					t.Errorf("invalid tag")
				}
				if html != "<b>" {
					t.Errorf("invalid tag html")
				}
				if options.IsClosing != false {
					t.Errorf("invalid tag isClosing")
				}
				if options.Position != 14 {
					t.Errorf("invalid tag Position")
				}
				if options.SourcePosition != 14 {
					t.Errorf("invalid tag sourcePosition")
				}

				if options.IsWhite != true {
					t.Errorf("invalid tag IsWhite")
				}
			}

			if i == 3 {
				if tag != "c" {
					t.Errorf("invalid tag")
				}
				if html != "<c>" {
					t.Errorf("invalid tag html")
				}
				if options.IsClosing != false {
					t.Errorf("invalid tag isClosing")
				}
				if options.Position != 17 {
					t.Errorf("invalid tag Position")
				}
				if options.SourcePosition != 17 {
					t.Errorf("invalid tag sourcePosition")
				}

				if options.IsWhite != false {
					t.Errorf("invalid tag IsWhite")
				}
			}

			if i == 4 {
				if tag != "c" {
					t.Errorf("invalid tag")
				}
				if html != "</c>" {
					t.Errorf("invalid tag html")
				}
				if options.IsClosing != true {
					t.Errorf("invalid tag isClosing")
				}
				if options.Position != 30 {
					t.Errorf("invalid tag Position")
				}
				if options.SourcePosition != 24 {
					t.Errorf("invalid tag sourcePosition")
				}

				if options.IsWhite != false {
					t.Errorf("invalid tag IsWhite")
				}
			}

			if i == 5 {
				if tag != "b" {
					t.Errorf("invalid tag")
				}
				if html != "</b>" {
					t.Errorf("invalid tag html")
				}
				if options.IsClosing != true {
					t.Errorf("invalid tag isClosing")
				}
				if options.Position != 40 {
					t.Errorf("invalid tag Position")
				}
				if options.SourcePosition != 28 {
					t.Errorf("invalid tag sourcePosition")
				}

				if options.IsWhite != true {
					t.Errorf("invalid tag IsWhite")
				}
			}

			if i == 6 {
				if tag != "a" {
					t.Errorf("invalid tag")
				}
				if html != "</a>" {
					t.Errorf("invalid tag html")
				}
				if options.IsClosing != true {
					t.Errorf("invalid tag isClosing")
				}
				if options.Position != 44 {
					t.Errorf("invalid tag Position")
				}
				if options.SourcePosition != 32 {
					t.Errorf("invalid tag sourcePosition")
				}

				if options.IsWhite != true {
					t.Errorf("invalid tag IsWhite")
				}
			}

			if i == 7 {
				if tag != "br" {
					t.Errorf("invalid tag")
				}
				if html != "<br>" {
					t.Errorf("invalid tag html")
				}
				if options.IsClosing != false {
					t.Errorf("invalid tag isClosing")
				}
				if options.Position != 48 {
					t.Errorf("invalid tag Position")
				}
				if options.SourcePosition != 36 {
					t.Errorf("invalid tag sourcePosition")
				}

				if options.IsWhite != true {
					t.Errorf("invalid tag IsWhite")
				}
			}

			return nil

		},
	})

	if html != "dd<a href=\"#\"><b>&lt;c&gt;haha&lt;/c&gt;</b></a><br>ff" {
		t.Errorf("FilterXSS error %s", html)
	}

}

func TestOnTagReturnNewHtml(t *testing.T) {

	source := "dd<a href=\"#\"><b><c>haha</c></b></a><br>ff"

	html := FilterXSS(source, XssOption{
		OnTag: func(tag, html string, options TagOption) *string {
			return &html
		},
	})

	if html != source {
		t.Errorf("TestOnTagReturnNewHtml error %s", html)
	}
}

func TestOnIgnoreTag(t *testing.T) {

	i := 0
	source := "dd<a href=\"#\"><b><c>haha</c></b></a><br>ff"
	html := FilterXSS(source, XssOption{
		OnIgnoreTag: func(tag, html string, options TagOption) *string {
			i++

			if i == 1 {
				if tag != "c" {
					t.Errorf("onIgnoreTag tag error %s", tag)

				}

				if html != "<c>" {
					t.Errorf("onIgnoreTag html error %s", html)

				}

				if options.IsClosing != false {
					t.Errorf("onIgnoreTag IsClosing error ")

				}

				if options.Position != 17 {
					t.Errorf("onIgnoreTag Position error ")

				}

				if options.SourcePosition != 17 {
					t.Errorf("onIgnoreTag SourcePosition error ")

				}

				if options.IsWhite != false {
					t.Errorf("onIgnoreTag IsWhite error ")

				}
			} else if i == 2 {
				if tag != "c" {
					t.Errorf("onIgnoreTag tag error %s", tag)

				}

				if html != "</c>" {
					t.Errorf("onIgnoreTag html error %s", html)

				}

				if options.IsClosing != true {
					t.Errorf("onIgnoreTag IsClosing error ")

				}

				if options.Position != 30 {
					t.Errorf("onIgnoreTag Position error ")

				}

				if options.SourcePosition != 24 {
					t.Errorf("onIgnoreTag SourcePosition error ")

				}

				if options.IsWhite != false {
					t.Errorf("onIgnoreTag IsWhite error ")

				}
			} else {
				t.Errorf("onIgnoreTag  error ")

			}
			return nil
		},
	})

	if html != "dd<a href=\"#\"><b>&lt;c&gt;haha&lt;/c&gt;</b></a><br>ff" {
		t.Errorf("onIgnoreTag error %s", html)
	}
}

func TestOnIgnoreTagReturnNewHtml(t *testing.T) {
	source := "dd<a href=\"#\"><b><c>haha</c></b></a><br>ff"
	html := FilterXSS(source, XssOption{
		OnIgnoreTag: func(tag, html string, options TagOption) *string {

			closeHtml := ""
			if options.IsClosing == true {
				closeHtml = "/"
			}
			ret := "[" + closeHtml + "removed]"
			return &ret
		},
	})

	if html != "dd<a href=\"#\"><b>[removed]haha[/removed]</b></a><br>ff" {
		t.Errorf("onIgnoreTag error %s", html)
	}
}

func TestOnTagAttr(t *testing.T) {
	source := "<a href=\"#\" target=\"_blank\" checked data-a=\"b\">hi</a href=\"d\">"

	i := 0
	html := FilterXSS(source, XssOption{
		OnTagAttr: func(tag, name, value string, isWhiteAttr bool) *string {
			i++

			if i == 1 {
				if name != "href" {
					t.Errorf("TestOnTagAttr error")
				}
				if value != "#" {
					t.Errorf("TestOnTagAttr error")
				}

				if isWhiteAttr != true {
					t.Errorf("TestOnTagAttr error")
				}
			} else if i == 2 {
				if name != "target" {
					t.Errorf("TestOnTagAttr error")
				}
				if value != "_blank" {
					t.Errorf("TestOnTagAttr error")
				}

				if isWhiteAttr != true {
					t.Errorf("TestOnTagAttr error")
				}
			} else if i == 3 {
				if name != "checked" {
					t.Errorf("TestOnTagAttr error")
				}
				if value != "" {
					t.Errorf("TestOnTagAttr error")
				}

				if isWhiteAttr != false {
					t.Errorf("TestOnTagAttr error")
				}
			} else if i == 4 {
				if name != "data-a" {
					t.Errorf("TestOnTagAttr error")
				}
				if value != "b" {
					t.Errorf("TestOnTagAttr error")
				}

				if isWhiteAttr != false {
					t.Errorf("TestOnTagAttr error")
				}
			} else {
				t.Errorf("TestOnTagAttr error")

			}
			return nil
		},
	})

	if html != "<a href=\"#\" target=\"_blank\">hi</a>" {
		t.Errorf("TestOnTagAttr error")
	}
}

func TestOnTagAttr2(t *testing.T) {
	source := "<a href=\"#\" target=\"_blank\" checked data-a=\"b\">hi</a href=\"d\">"

	// i := 0
	html := FilterXSS(source, XssOption{
		OnTagAttr: func(tag, name, value string, isWhiteAttr bool) *string {
			ret := "$" + name + "$"
			return &ret
		},
	})

	if html != "<a $href$ $target$ $checked$ $data-a$>hi</a>" {
		t.Errorf("TestOnTagAttr error")
	}
}

func TestOnIgnoreTagAttr(t *testing.T) {
	source := "<a href=\"#\" target=\"_blank\" checked data-a=\"b\">hi</a href=\"d\">"

	i := 0
	html := FilterXSS(source, XssOption{
		OnIgnoreTagAttr: func(tag, name, value string, isWhiteAttr bool) *string {
			i++

			if tag != "a" {
				t.Errorf("TestOnIgnoreTagAttr error")
			}

			if i == 1 {
				if name != "checked" {
					t.Errorf("TestOnIgnoreTagAttr error")
				}
				if value != "" {
					t.Errorf("TestOnIgnoreTagAttr error")
				}

				if isWhiteAttr != false {
					t.Errorf("TestOnIgnoreTagAttr error")
				}
			} else if i == 2 {
				if name != "data-a" {
					t.Errorf("TestOnIgnoreTagAttr error")
				}
				if value != "b" {
					t.Errorf("TestOnIgnoreTagAttr error")
				}

				if isWhiteAttr != false {
					t.Errorf("TestOnIgnoreTagAttr error")
				}
			} else {
				t.Errorf("TestOnIgnoreTagAttr error")

			}
			return nil
		},
	})

	if html != "<a href=\"#\" target=\"_blank\">hi</a>" {
		t.Errorf("TestOnTagAttr error")

	}
}

// TestOnIgnoreWhiteListTagNullAttr 测试忽略tag 空属性
func TestOnIgnoreWhiteListTagNullAttr(t *testing.T) {
	source := "<a    >bb</a>"

	html := FilterXSS(source, XssOption{WhiteList: GetDefaultWhiteList()})

	if html != "<a>bb</a>" {
		t.Errorf("TestOnIgnoreWhiteListTagNullAttr error")
	}
}

func TestOnIgnoreTagAttrWithReturn(t *testing.T) {
	source := "<a href=\"#\" target=\"_blank\" checked data-a=\"b\">hi</a href=\"d\">"

	html := FilterXSS(source, XssOption{
		OnIgnoreTagAttr: func(tag, name, value string, isWhiteAttr bool) *string {

			ret := "$" + name + "$"
			return &ret
		},
	})

	if html != "<a href=\"#\" target=\"_blank\" $checked$ $data-a$>hi</a>" {
		t.Errorf("TestOnTagAttr error")

	}
}
func TestEscapeDefault(t *testing.T) {
	source := "<x>yy</x><a>bb</a>"

	html := FilterXSS(source, XssOption{})

	if html != "&lt;x&gt;yy&lt;/x&gt;<a>bb</a>" {
		t.Errorf("TestEscapeDefault error")

	}
}

func TestEscapeReturn(t *testing.T) {
	source := "<x>yy</x><a>bb</a>"

	html := FilterXSS(source, XssOption{
		EscapeHTML: func(str string) string {

			ret := ""
			if len(str) > 0 {
				ret = "[" + str + "]"
			}
			return ret
		},
	})

	if html != "[<x>][yy][</x>]<a>[bb]</a>" {
		t.Errorf("TestEscapeReturn error %s", html)

	}
}

func TestSafeAttrValueDefault(t *testing.T) {
	source := "<a href=\"javascript:alert(/xss/)\" title=\"hi\">link</a>"

	html := FilterXSS(source, XssOption{})

	if html != "<a href title=\"hi\">link</a>" {
		t.Errorf("TestSafeAttrValueReturn error")

	}
}

func TestSafeAttrValueReturn(t *testing.T) {
	source := "<a href=\"javascript:alert(/xss/)\" title=\"hi\">link</a>"

	html := FilterXSS(source, XssOption{
		SafeAttrValue: func(tag, name, value string, cssFilter *cssfilter.FilterCSS) string {

			ret := "$" + name + "$"
			if name == "style" && cssFilter != nil {
				ret = cssFilter.Process(ret)
			}

			return ret
		},
	})

	if html != "<a href=\"$href$\" title=\"$title$\">link</a>" {
		t.Errorf("TestSafeAttrValueReturn error %s", html)

	}
}

func TestStripIngoreTag(t *testing.T) {
	source := "<x>yy</x><a>bb</a>"

	html := FilterXSS(source, XssOption{StripIgnoreTag: true})

	if html != "yy<a>bb</a>" {
		t.Errorf("TestStripIngoreTag error %s", html)

	}
}

func TestStripIngoreBodyTag(t *testing.T) {
	source := "<a>link</a><x>haha</x><y>a<y></y>b</y>k"

	html := FilterXSS(source, XssOption{StripIgnoreTagBody: []string{}})

	if html != "<a>link</a>bk" {
		t.Errorf("TestStripIngoreTag error %s", html)

	}
}

func TestStripIngoreBodyTag2(t *testing.T) {
	source := "<a>link</a><x>haha</x><y>a<y></y>b</y>k"

	html := FilterXSS(source, XssOption{StripIgnoreTagBody: []string{"x"}})

	if html != "<a>link</a>&lt;y&gt;a&lt;y&gt;&lt;/y&gt;b&lt;/y&gt;k" {
		t.Errorf("TestStripIngoreBodyTag2 error %s", html)

	}
}

func TestStripIngoreBodyTag3(t *testing.T) {
	source := "<a>link</a><x>haha</x><y>a<y></y>b</y>k"

	html := FilterXSS(source, XssOption{
		StripIgnoreTagBody: []string{"x"},
		OnIgnoreTag: func(tag, html string, options TagOption) *string {

			ret := "$" + tag + "$"
			return &ret
		},
	})

	if html != "<a>link</a>$y$a$y$$y$b$y$k" {
		t.Errorf("TestStripIngoreBodyTag2 error %s", html)

	}
}

func TestStripIngoreBodyTag4(t *testing.T) {
	source := "<scri" + "pt>alert(/xss/);</scri" + "pt>"

	html := FilterXSS(source, XssOption{
		StripIgnoreTagBody: []string{"script"},
		StripIgnoreTag:     true,
	})

	if html != "" {
		t.Errorf("TestStripIngoreBodyTag4 error %s", html)

	}
}

func TestStripIngoreBodyTag5(t *testing.T) {
	source := "ooxx<scri" + "pt>alert(/xss/);</scri" + "pt>"

	html := FilterXSS(source, XssOption{
		StripIgnoreTagBody: []string{"script"},
		StripIgnoreTag:     true,
	})

	if html != "ooxx" {
		t.Errorf("TestStripIngoreBodyTag4 error %s", html)

	}
}

func TestOnTagSanitizeHtml(t *testing.T) {

	source := "<a target= \" href=\"><script>alert(2)</script>\"><span>"

	html := FilterXSS(source, XssOption{
		OnTag: func(tag, html string, options TagOption) *string {
			if options.IsWhite && "a" == tag {
				if options.IsClosing {
					ret := "</span></a>"
					return &ret
				}
				ret := html + "<span>"
				return &ret
			}
			return nil
		},
	})

	if html != "<a target= \" href=\"><span>&lt;script&gt;alert(2)&lt;/script&gt;\"&gt;<span>" {
		t.Errorf("TestStripIngoreBodyTag4 error %s", html)
	}
}

func TestSingleQuotedAttributeValue(t *testing.T) {
	source := "<a title=\"xx\">single-quoted</a>"

	html := FilterXSS(source, XssOption{SingleQuotedAttributeValue: false})

	if html != "<a title=\"xx\">single-quoted</a>" {
		t.Errorf("TestSingleQuotedAttributeValue expect: %s but:%s", source, html)

	}

	html = FilterXSS(source, XssOption{SingleQuotedAttributeValue: true})

	expect := "<a title='xx'>single-quoted</a>"
	if html != expect {
		t.Errorf("TestSingleQuotedAttributeValue expect:%s  but:%s", expect, html)

	}

	source = "<a title='xx'>single-quoted</a>"

	html = FilterXSS(source, XssOption{SingleQuotedAttributeValue: false})
	expect = "<a title=\"xx\">single-quoted</a>"
	if html != expect {
		t.Errorf("TestSingleQuotedAttributeValue expect: %s but:%s", expect, html)

	}
}

func TestFilterWithCssFilter(t *testing.T) {
	source := `<div style="position: fixed; width:100px; height: 200px; background: url (xxx);">hello</div>`

	xssOption := NewDefaultXssOption()
	xssOption.EnableCssFilter = true
	xssOption.WhiteList["div"] = []string{"style"}

	html := FilterXSS(source, xssOption)

	expect := `<div style="width:100px; height:200px; background:url (xxx);">hello</div>`
	if html != expect {
		t.Errorf("TestFilterWithCssFilter expect: %s but:%s", expect, html)

	}

}
