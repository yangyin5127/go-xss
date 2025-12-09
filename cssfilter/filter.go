package cssfilter

// 等价 JS isNull：nil → true
func isNull(v interface{}) bool {
	return v == nil
}

// ---------- FilterCSS 核心 ----------

type FilterCSS struct {
	Options CssOption
}

// 新建 FilterCSS（浅拷贝 semantics）
func NewFilterCSS(opt *CssOption) *FilterCSS {
	var cfg CssOption
	if opt != nil {
		cfg = *opt
	}

	// 白名单为空时，默认空 map
	if cfg.WhiteList == nil {
		cfg.WhiteList = DefaultCssWhiteList
	}

	// 默认回调
	if cfg.OnAttr == nil {
		cfg.OnAttr = func(name, value string, opts StyleAttrOption) *string {
			return nil
		}
	}
	if cfg.OnIgnoreAttr == nil {
		cfg.OnIgnoreAttr = func(name, value string, opts StyleAttrOption) *string {
			return nil
		}
	}
	if cfg.SafeAttrValue == nil {
		cfg.SafeAttrValue = SafeAttrValue
	}

	return &FilterCSS{Options: cfg}
}

func (fc *FilterCSS) Process(css string) string {
	if css == "" {
		return ""
	}

	opts := fc.Options
	white := opts.WhiteList
	onAttr := opts.OnAttr
	onIgnore := opts.OnIgnoreAttr
	safeAttrValue := opts.SafeAttrValue

	result := ParseStyle(css, func(sourcePos, position int, name, value, source string) string {

		// ---- whitelist check ----
		check, exists := white[name]
		isWhite := false
		if exists {
			if check.Allow {
				isWhite = true
			} else if check.Func != nil {
				isWhite = check.Func(value)
			} else if check.Reg != nil {
				isWhite = check.Reg.MatchString(value)
			}
		}

		// ---- safeAttrValue ----
		value = safeAttrValue(name, value)
		if value == "" {
			return ""
		}

		optsObj := StyleAttrOption{
			Position:       position,
			SourcePosition: sourcePos,
			Source:         source,
			IsWhite:        isWhite,
		}

		if isWhite && onAttr != nil {
			// onAttr 可返回 nil → 默认 name:value
			ret := onAttr(name, value, optsObj)

			if ret == nil {
				return name + ":" + value
			}
			return *ret
		}

		// not whitelisted
		ret := onIgnore(name, value, optsObj)
		if ret != nil {
			return *ret
		}

		return ""
	})

	return result
}
