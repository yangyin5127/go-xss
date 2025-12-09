package cssfilter

import "testing"

func TestSafeAttrValue(t *testing.T) {
	sourceName := "href"
	sourceValue := "javascript:alert(1);"
	result := SafeAttrValue(sourceName, sourceValue)
	if result != "" {
		t.Errorf("TestSafeAttrValue err %v", result)
	}

	sourceName = "src"
	sourceValue = "javascript:alert(1);"
	result = SafeAttrValue(sourceName, sourceValue)
	if result != "" {
		t.Errorf("TestSafeAttrValue err %v", result)
	}

	sourceName = "style"
	sourceValue = "background-image: url(javascript:alert(1));"
	result = SafeAttrValue(sourceName, sourceValue)
	if result != "" {
		t.Errorf("TestSafeAttrValue err %v", result)
	}
}
