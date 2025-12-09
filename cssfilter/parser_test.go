package cssfilter

import "testing"

func TestParseStyleStripBlankChars(t *testing.T) {
	result := ParseStyle("width: 100px;\nheight:200px;   font-size:400;", func(sourcePosition, position int, name, value, source string) string {
		if name == "width" && value != "100px" {
			t.Fatalf("width value expected 100px, got %s", value)
		}
		if name == "height" && value != "200px" {
			t.Fatalf("height value expected 200px, got %s", value)
		}
		if name == "font-size" && value != "400" {
			t.Fatalf("font-size value expected 400, got %s", value)
		}
		return name + ":" + value
	})

	expected := "width:100px; height:200px; font-size:400;"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}
}

func TestParseStyleStripComments(t *testing.T) {
	css := "/*width: 100px;\nhe*/ight:200px; /**/ y:url(a/*b*/); /*font-size:400; */font:none;"
	result := ParseStyle(css, func(sourcePosition, position int, name, value, source string) string {
		if name == "font" && value != "none" {
			t.Fatalf("font value expected none, got %s", value)
		}
		return name + ":" + value
	})

	expected := "ight:200px; font:none;"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}
}

func TestParseStyleEndingWithoutSemicolon(t *testing.T) {
	result := ParseStyle("width: 100px;height:200px;    font-size:400", func(sourcePosition, position int, name, value, source string) string {
		if name == "width" && value != "100px" {
			t.Fatalf("width expected 100px, got %s", value)
		}
		if name == "height" && value != "200px" {
			t.Fatalf("height expected 200px, got %s", value)
		}
		if name == "font-size" && value != "400" {
			t.Fatalf("font-size expected 400, got %s", value)
		}
		return name + ":" + value
	})

	expected := "width:100px; height:200px; font-size:400;"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}
}

func TestParseStyleInsideParentheses(t *testing.T) {

	// url(xxx)
	result := ParseStyle("width: 100px;height:200px;  background:url(xxx);  font-size:400",
		func(sourcePosition, position int, name, value, source string) string {
			switch name {
			case "width":
				if value != "100px" {
					t.Fatalf("width expected 100px, got %s", value)
				}
			case "height":
				if value != "200px" {
					t.Fatalf("height expected 200px, got %s", value)
				}
			case "font-size":
				if value != "400" {
					t.Fatalf("font-size expected 400, got %s", value)
				}
			case "background":
				if value != "url(xxx)" {
					t.Fatalf("background expected url(xxx), got %s", value)
				}
			}
			return name + ":" + value
		},
	)
	expected := "width:100px; height:200px; background:url(xxx); font-size:400;"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}

	// url(x;x;x)
	result = ParseStyle("width: 100px;height:200px;  background:url(x;x;x);  font-size:400",
		func(sourcePosition, position int, name, value, source string) string {
			switch name {
			case "width":
				if value != "100px" {
					t.Fatalf("width expected 100px, got %s", value)
				}
			case "height":
				if value != "200px" {
					t.Fatalf("height expected 200px, got %s", value)
				}
			case "font-size":
				if value != "400" {
					t.Fatalf("font-size expected 400, got %s", value)
				}
			case "background":
				if value != "url(x;x;x)" {
					t.Fatalf("background expected url(x;x;x), got %s", value)
				}
			}
			return name + ":" + value
		},
	)
	expected = "width:100px; height:200px; background:url(x;x;x); font-size:400;"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}

	// url(xx\nx) → invalid because newline inside () breaks rule, so background should be ignored
	result = ParseStyle("width: 100px;height:200px;  background:url(xx\nx);  font-size:400",
		func(sourcePosition, position int, name, value, source string) string {
			switch name {
			case "width":
				if value != "100px" {
					t.Fatalf("width expected 100px, got %s", value)
				}
			case "height":
				if value != "200px" {
					t.Fatalf("height expected 200px, got %s", value)
				}
			case "font-size":
				if value != "400" {
					t.Fatalf("font-size expected 400, got %s", value)
				}
			}
			return name + ":" + value
		},
	)
	expected = "width:100px; height:200px; font-size:400;"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}
}
