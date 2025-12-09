package cssfilter

import (
	"testing"
)

func eq(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("expected `%s`, got `%s`", want, got)
	}
}

func ok(t *testing.T, condition bool, msg string) {
	t.Helper()
	if !condition {
		t.Fatal(msg)
	}
}

func TestFilterCSS_Normal(t *testing.T) {
	fc := NewFilterCSS(nil)

	result := fc.Process("00xx; position: fixed; width:100px; height:  200px")
	eq(t, result, "width:100px; height:200px;")

	fc = NewFilterCSS(&CssOption{
		OnAttr: func(name, value string, opts StyleAttrOption) *string {
			ok(t, opts.IsWhite, "expected IsWhite true")
			if name == "width" {
				eq(t, value, "100px")
			} else if name == "height" {
				eq(t, value, "200px")
			} else {
				t.Fatalf("bad attr name `%s`", name)
			}
			return nil
		},
		OnIgnoreAttr: func(name, value string, opts StyleAttrOption) *string {
			ok(t, !opts.IsWhite, "expected IsWhite false")
			if name == "position" {
				eq(t, value, "fixed")
			} else {
				t.Fatalf("bad attr name `%s`", name)
			}
			return nil
		},
	})

	result = fc.Process("position: fixed; width:100px; height:  200px")
	eq(t, result, "width:100px; height:200px;")
}

func TestFilterCSS_OnAttrReturnNewSource(t *testing.T) {
	fc := NewFilterCSS(&CssOption{
		OnAttr: func(name, value string, opts StyleAttrOption) *string {
			ok(t, opts.IsWhite, "expected IsWhite true")
			ret := name + ": " + value
			return &ret
		},
	})

	result := fc.Process("position: fixed; width:100px; height:  200px")
	eq(t, result, "width: 100px; height: 200px;")
}

func TestFilterCSS_OnIgnoreAttrReturnNewSource(t *testing.T) {
	fc := NewFilterCSS(&CssOption{
		OnIgnoreAttr: func(name, value string, opts StyleAttrOption) *string {
			ok(t, !opts.IsWhite, "expected IsWhite false")
			if name == "position" {
				ret := "x-" + name + ":" + value
				return &ret
			}
			return nil
		},
	})

	result := fc.Process("position: fixed; width:100px; height:  200px")
	eq(t, result, "x-position:fixed; width:100px; height:200px;")
}

func TestFilterCSS_SafeAttrValue(t *testing.T) {
	fc := NewFilterCSS(nil)

	tests := []struct {
		input  string
		expect string
	}{
		{"background: url(javascript:alert(/xss/)); height: 400px;", "height:400px;"},
		{"background: url( javascript : alert(/xss/)); height: 400px;", "height:400px;"},
		{"background: url ( javascript :alert(/xss/)); height: 400px;", "height:400px;"},
		{"background: url (\" javascript :alert(/xss/)\"); height: 400px;", "height:400px;"},
		{"background: url ( javascript : \"alert(/xss/) \"); height: 400px;", "height:400px;"},
		{"background: url ( java script : alert(/xss/)); height: 400px;", "background:url ( java script : alert(/xss/)); height:400px;"},
	}

	for _, test := range tests {
		result := fc.Process(test.input)
		eq(t, result, test.expect)
	}
}
