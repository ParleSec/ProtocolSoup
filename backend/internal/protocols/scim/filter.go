package scim

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SCIM filters (RFC 7644 Section 3.4.2.2) and PATCH paths (Section 3.5.2).
// The parser follows the ABNF of Figure 1:
//
//	FILTER    = attrExp / logExp / valuePath / *1"not" "(" FILTER ")"
//	valuePath = attrPath "[" valFilter "]"
//	valFilter = attrExp / logExp / *1"not" "(" valFilter ")"
//	attrExp   = (attrPath SP "pr") / (attrPath SP compareOp SP compValue)
//	logExp    = FILTER SP ("and" / "or") SP FILTER
//	compValue = false / null / true / number / string
//	attrPath  = [URI ":"] ATTRNAME *1subAttr
//
// A filter is evaluated in memory against the JSON of each resource, with the
// attribute definitions of schema.go deciding type and case sensitivity.

// attrPath is the ABNF rule attrPath.
type attrPath struct {
	Schema string // the schema URI, or "" when the client omitted it
	Name   string
	Sub    string
}

func (p attrPath) String() string {
	out := p.Name
	if p.Schema != "" {
		out = p.Schema + ":" + out
	}
	if p.Sub != "" {
		out += "." + p.Sub
	}
	return out
}

// filterNode is one node of a parsed filter.
type filterNode interface{ String() string }

// attrExpr is attrExp: a comparison, or a presence test when Op is "pr".
type attrExpr struct {
	Path  attrPath
	Op    string
	Value interface{}
}

// logExpr is logExp.
type logExpr struct {
	Op          string // "and" or "or"
	Left, Right filterNode
}

// notExpr is "not" "(" FILTER ")".
type notExpr struct{ Expr filterNode }

// valuePathExpr is valuePath: Filter applies to the sub-attributes of each
// value of Path, and matches when one value satisfies all of it.
type valuePathExpr struct {
	Path   attrPath
	Filter filterNode
}

func (e *attrExpr) String() string {
	if e.Op == "pr" {
		return e.Path.String() + " pr"
	}
	value, _ := json.Marshal(e.Value)
	return e.Path.String() + " " + e.Op + " " + string(value)
}
func (e *logExpr) String() string {
	return "(" + e.Left.String() + " " + e.Op + " " + e.Right.String() + ")"
}
func (e *notExpr) String() string       { return "not (" + e.Expr.String() + ")" }
func (e *valuePathExpr) String() string { return e.Path.String() + "[" + e.Filter.String() + "]" }

// compareOps are the attribute operators of Table 3 that take a value.
var compareOps = map[string]bool{"eq": true, "ne": true, "co": true, "sw": true, "ew": true, "gt": true, "lt": true, "ge": true, "le": true}

// attrNamePattern is ATTRNAME = ALPHA *(nameChar), with the "$" of "$ref".
var attrNamePattern = regexp.MustCompile(`^[A-Za-z$][A-Za-z0-9_$-]*$`)

// ================== Lexer ==================

type filterToken struct {
	kind string // "(", ")", "[", "]", "string", "word" or "end"
	text string
}

// lexFilter splits a filter into brackets, JSON strings and words. A word is
// an attribute path, an operator or a literal.
func lexFilter(input string) ([]filterToken, error) {
	var tokens []filterToken
	for i := 0; i < len(input); {
		c := input[i]
		switch c {
		case ' ', '\t', '\r', '\n':
			i++
		case '(', ')', '[', ']':
			tokens = append(tokens, filterToken{kind: string(c)})
			i++
		case '"':
			end := i + 1
			for end < len(input) && input[end] != '"' {
				if input[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(input) {
				return nil, fmt.Errorf("a string that starts at position %d is not closed", i+1)
			}
			tokens = append(tokens, filterToken{kind: "string", text: input[i : end+1]})
			i = end + 1
		default:
			end := i
			for end < len(input) && !strings.ContainsRune(" \t\r\n()[]\"", rune(input[end])) {
				end++
			}
			tokens = append(tokens, filterToken{kind: "word", text: input[i:end]})
			i = end
		}
	}
	return append(tokens, filterToken{kind: "end"}), nil
}

// ================== Parser ==================

type filterParser struct {
	tokens []filterToken
	pos    int
}

func (p *filterParser) peek() filterToken { return p.tokens[p.pos] }
func (p *filterParser) next() filterToken {
	token := p.tokens[p.pos]
	if token.kind != "end" {
		p.pos++
	}
	return token
}

// isWord reports whether the next token is the given keyword. "Attribute
// names and attribute operators used in filters are case insensitive."
func (p *filterParser) isWord(keyword string) bool {
	token := p.peek()
	return token.kind == "word" && strings.EqualFold(token.text, keyword)
}

func describeToken(token filterToken) string {
	switch token.kind {
	case "end":
		return "the end of the filter"
	case "word", "string":
		return token.text
	default:
		return token.kind
	}
}

// ParseFilter parses a filter expression.
func ParseFilter(input string) (filterNode, error) {
	if strings.TrimSpace(input) == "" {
		// "The filter parameter MUST contain at least one valid expression".
		return nil, fmt.Errorf("the filter is empty")
	}
	tokens, err := lexFilter(input)
	if err != nil {
		return nil, err
	}
	parser := &filterParser{tokens: tokens}
	node, err := parser.parseOr(false)
	if err != nil {
		return nil, err
	}
	if token := parser.peek(); token.kind != "end" {
		return nil, fmt.Errorf("unexpected %s after the expression", describeToken(token))
	}
	return node, nil
}

// "Filters MUST be evaluated using the following order of operations": the
// grouping operators, then the logical operators, 'where "not" takes
// precedence over "and", which takes precedence over "or"', then the
// attribute operators. inValue is true inside the brackets of a valuePath,
// where the grammar is valFilter.
func (p *filterParser) parseOr(inValue bool) (filterNode, error) {
	left, err := p.parseAnd(inValue)
	if err != nil {
		return nil, err
	}
	for p.isWord("or") {
		p.next()
		right, err := p.parseAnd(inValue)
		if err != nil {
			return nil, err
		}
		left = &logExpr{Op: "or", Left: left, Right: right}
	}
	return left, nil
}

func (p *filterParser) parseAnd(inValue bool) (filterNode, error) {
	left, err := p.parseUnary(inValue)
	if err != nil {
		return nil, err
	}
	for p.isWord("and") {
		p.next()
		right, err := p.parseUnary(inValue)
		if err != nil {
			return nil, err
		}
		left = &logExpr{Op: "and", Left: left, Right: right}
	}
	return left, nil
}

func (p *filterParser) parseUnary(inValue bool) (filterNode, error) {
	negated := false
	if p.isWord("not") {
		p.next()
		negated = true
		if p.peek().kind != "(" {
			return nil, fmt.Errorf("expected ( after not, got %s", describeToken(p.peek()))
		}
	}
	if p.peek().kind == "(" {
		p.next()
		inner, err := p.parseOr(inValue)
		if err != nil {
			return nil, err
		}
		if token := p.next(); token.kind != ")" {
			return nil, fmt.Errorf("expected ), got %s", describeToken(token))
		}
		if negated {
			return &notExpr{Expr: inner}, nil
		}
		return inner, nil
	}
	return p.parseAttrExpr(inValue)
}

func (p *filterParser) parseAttrExpr(inValue bool) (filterNode, error) {
	token := p.next()
	if token.kind != "word" {
		return nil, fmt.Errorf("expected an attribute name, got %s", describeToken(token))
	}
	path, err := parseAttrPath(token.text)
	if err != nil {
		return nil, err
	}
	if p.peek().kind == "[" {
		if inValue {
			return nil, fmt.Errorf("a value filter cannot hold another value filter")
		}
		if path.Sub != "" {
			return nil, fmt.Errorf("the value filter of %s must follow the attribute, not a sub-attribute", path)
		}
		p.next()
		inner, err := p.parseOr(true)
		if err != nil {
			return nil, err
		}
		if token := p.next(); token.kind != "]" {
			return nil, fmt.Errorf("expected ], got %s", describeToken(token))
		}
		return &valuePathExpr{Path: path, Filter: inner}, nil
	}

	operator := p.next()
	if operator.kind != "word" {
		return nil, fmt.Errorf("expected an operator after %s, got %s", path, describeToken(operator))
	}
	op := strings.ToLower(operator.text)
	if op == "pr" {
		return &attrExpr{Path: path, Op: "pr"}, nil
	}
	if !compareOps[op] {
		// "Providers MUST decline to filter results if the specified filter
		// operation is not recognized".
		return nil, fmt.Errorf("the operator '%s' is not supported", operator.text)
	}
	value, err := parseCompValue(p.next())
	if err != nil {
		return nil, err
	}
	return &attrExpr{Path: path, Op: op, Value: value}, nil
}

// parseAttrPath parses attrPath = [URI ":"] ATTRNAME *1subAttr. The schema
// URI ends at the last colon: the name after it has no colon in it.
func parseAttrPath(text string) (attrPath, error) {
	var path attrPath
	rest := text
	if colon := strings.LastIndex(text, ":"); colon >= 0 {
		path.Schema, rest = text[:colon], text[colon+1:]
		if !strings.HasPrefix(strings.ToLower(path.Schema), "urn:") {
			return path, fmt.Errorf("%q does not start with a schema URI", text)
		}
	}
	path.Name, path.Sub, _ = strings.Cut(rest, ".")
	if !attrNamePattern.MatchString(path.Name) || (strings.Contains(rest, ".") && !attrNamePattern.MatchString(path.Sub)) {
		return path, fmt.Errorf("%q is not an attribute path", text)
	}
	return path, nil
}

// parseCompValue parses compValue = false / null / true / number / string,
// with the "rules from JSON (RFC 7159)".
func parseCompValue(token filterToken) (interface{}, error) {
	if token.kind != "string" && token.kind != "word" {
		return nil, fmt.Errorf("expected a value to compare with, got %s", describeToken(token))
	}
	var value interface{}
	if err := json.Unmarshal([]byte(token.text), &value); err != nil {
		return nil, fmt.Errorf("%s is not a JSON string, number, true, false or null", token.text)
	}
	switch value.(type) {
	case nil, bool, float64, string:
		return value, nil
	default:
		return nil, fmt.Errorf("%s is not a JSON string, number, true, false or null", token.text)
	}
}

// patchPath is the PATCH PATH rule of Figure 7: PATH = attrPath / valuePath
// [subAttr].
type patchPath struct {
	Attr   attrPath   // the attribute; Sub is set for attrPath with a subAttr
	Filter filterNode // the valFilter of a valuePath, or nil
	Sub    string     // the subAttr that follows a valuePath
}

// ParsePatchPath parses the "path" of a PATCH operation.
func ParsePatchPath(input string) (patchPath, error) {
	var path patchPath
	tokens, err := lexFilter(input)
	if err != nil {
		return path, err
	}
	parser := &filterParser{tokens: tokens}
	first := parser.next()
	if first.kind != "word" {
		return path, fmt.Errorf("expected an attribute name, got %s", describeToken(first))
	}
	if path.Attr, err = parseAttrPath(first.text); err != nil {
		return path, err
	}
	if parser.peek().kind == "[" {
		if path.Attr.Sub != "" {
			return path, fmt.Errorf("the value filter of %s must follow the attribute, not a sub-attribute", path.Attr)
		}
		parser.next()
		if path.Filter, err = parser.parseOr(true); err != nil {
			return path, err
		}
		if token := parser.next(); token.kind != "]" {
			return path, fmt.Errorf("expected ], got %s", describeToken(token))
		}
		if token := parser.peek(); token.kind == "word" && strings.HasPrefix(token.text, ".") {
			parser.next()
			path.Sub = token.text[1:]
			if !attrNamePattern.MatchString(path.Sub) {
				return path, fmt.Errorf("%q is not a sub-attribute", token.text)
			}
		}
	}
	if token := parser.peek(); token.kind != "end" {
		return path, fmt.Errorf("unexpected %s after the path", describeToken(token))
	}
	return path, nil
}

// ================== Evaluation ==================

// matchResource evaluates a filter against one resource.
func matchResource(node filterNode, resource map[string]interface{}, schema *resourceSchema) (bool, error) {
	return evalFilter(node, func(path attrPath) (*Attribute, []interface{}) { return schema.leaves(resource, path) },
		func(path attrPath) (*Attribute, []interface{}) {
			found, ok := schema.locate(path)
			if !ok {
				return nil, nil
			}
			raw := found.container(resource, false)[found.def.Name]
			if values, isArray := raw.([]interface{}); isArray {
				return found.def, values
			}
			if raw == nil {
				return found.def, nil
			}
			return found.def, []interface{}{raw}
		})
}

// matchValue evaluates the valFilter of a valuePath against one value of a
// complex attribute: its paths name that attribute's sub-attributes.
func matchValue(node filterNode, def *Attribute, value map[string]interface{}) (bool, error) {
	return evalFilter(node, func(path attrPath) (*Attribute, []interface{}) {
		sub := findAttribute(def.SubAttributes, path.Name)
		if sub == nil || path.Schema != "" || path.Sub != "" {
			return nil, nil
		}
		if raw := value[sub.Name]; assigned(raw) {
			return sub, []interface{}{raw}
		}
		return sub, nil
	}, nil)
}

// evalFilter walks a filter. leaves gives the values a path selects; elements
// gives the values of a complex attribute, for a valuePath.
func evalFilter(node filterNode, leaves, elements func(attrPath) (*Attribute, []interface{})) (bool, error) {
	switch expr := node.(type) {
	case *logExpr:
		left, err := evalFilter(expr.Left, leaves, elements)
		if err != nil {
			return false, err
		}
		right, err := evalFilter(expr.Right, leaves, elements)
		if err != nil {
			return false, err
		}
		if expr.Op == "and" {
			return left && right, nil
		}
		return left || right, nil
	case *notExpr:
		inner, err := evalFilter(expr.Expr, leaves, elements)
		return !inner, err
	case *valuePathExpr:
		// "expressions MUST be applied to the same value of a parent
		// attribute specified immediately before the left square bracket".
		def, values := elements(expr.Path)
		if def == nil {
			return false, nil
		}
		if def.Type != "complex" {
			return false, fmt.Errorf("%s is not a complex attribute, so it takes no value filter", expr.Path)
		}
		for _, value := range values {
			object, _ := value.(map[string]interface{})
			matched, err := matchValue(expr.Filter, def, object)
			if err != nil || matched {
				return matched, err
			}
		}
		return false, nil
	case *attrExpr:
		def, values := leaves(expr.Path)
		if expr.Op == "pr" {
			// "If the attribute has a non-empty or non-null value, or if it
			// contains a non-empty node for complex attributes, there is a
			// match."
			return len(values) > 0, nil
		}
		if expr.Value == nil {
			// null stands for no value.
			return (expr.Op == "eq" && len(values) == 0) || (expr.Op == "ne" && len(values) > 0), nil
		}
		if def == nil {
			// An undefined attribute has no value: "a presence or equality
			// filter for an undefined attribute evaluates to false".
			return expr.Op == "ne", nil
		}
		if err := checkComparison(def, expr); err != nil {
			return false, err
		}
		if expr.Op == "ne" {
			// "The attribute and operator values are not identical."
			for _, value := range values {
				if equal, _ := compareValue(def, "eq", value, expr.Value); equal {
					return false, nil
				}
			}
			return true, nil
		}
		// "If the specified attribute in a filter expression is a
		// multi-valued attribute, the filter matches if any of the values of
		// the specified attribute match the specified criterion".
		for _, value := range values {
			if matched, _ := compareValue(def, expr.Op, value, expr.Value); matched {
				return true, nil
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("unsupported filter expression")
}

// checkComparison refuses a comparison the attribute's type does not
// support. Table 9, invalidFilter: "the specified attribute and filter
// comparison combination is not supported."
func checkComparison(def *Attribute, expr *attrExpr) error {
	ordering := expr.Op == "gt" || expr.Op == "ge" || expr.Op == "lt" || expr.Op == "le"
	substring := expr.Op == "co" || expr.Op == "sw" || expr.Op == "ew"
	_, isString := expr.Value.(string)
	_, isBool := expr.Value.(bool)
	_, isNumber := expr.Value.(float64)
	switch def.Type {
	case "boolean", "binary":
		// Table 3, for gt, ge, lt and le: "Boolean and Binary attributes
		// SHALL cause a failed response (HTTP status code 400) with
		// "scimType" of "invalidFilter"."
		if ordering {
			return fmt.Errorf("%s is a %s attribute, which the operator %s does not apply to", expr.Path, def.Type, expr.Op)
		}
		if def.Type == "boolean" && (!isBool || substring) {
			return fmt.Errorf("%s is a boolean attribute: compare it to true or false with eq or ne", expr.Path)
		}
		if def.Type == "binary" && !isString {
			return fmt.Errorf("%s is a binary attribute: compare it to a string", expr.Path)
		}
	case "integer", "decimal":
		if !isNumber || substring {
			return fmt.Errorf("%s is a numeric attribute: compare it to a number", expr.Path)
		}
	case "dateTime":
		if !isString {
			return fmt.Errorf("%s is a dateTime attribute: compare it to a string", expr.Path)
		}
		if _, err := time.Parse(time.RFC3339Nano, expr.Value.(string)); err != nil && !substring {
			return fmt.Errorf("%q is not a dateTime to compare %s with", expr.Value, expr.Path)
		}
	case "complex":
		return fmt.Errorf("%s is a complex attribute: name one of its sub-attributes", expr.Path)
	default:
		if !isString {
			return fmt.Errorf("%s is a %s attribute: compare it to a string", expr.Path, def.Type)
		}
	}
	return nil
}

// compareValue applies one operator of Table 3 to one attribute value. "The
// actual comparison is dependent on the attribute type."
func compareValue(def *Attribute, op string, actual, expected interface{}) (bool, error) {
	order := 0
	switch def.Type {
	case "boolean":
		a, _ := actual.(bool)
		e, _ := expected.(bool)
		return (a == e) == (op == "eq"), nil
	case "integer", "decimal":
		a, ok := actual.(float64)
		if !ok {
			return false, nil
		}
		e := expected.(float64)
		switch {
		case a < e:
			order = -1
		case a > e:
			order = 1
		}
	case "dateTime":
		// "for DateTime types, it is a chronological comparison."
		a, aErr := time.Parse(time.RFC3339Nano, fmt.Sprint(actual))
		e, eErr := time.Parse(time.RFC3339Nano, fmt.Sprint(expected))
		if aErr != nil || eErr != nil || op == "co" || op == "sw" || op == "ew" {
			return compareText(op, fmt.Sprint(actual), fmt.Sprint(expected)), nil
		}
		order = a.Compare(e)
	default:
		a, _ := actual.(string)
		e, _ := expected.(string)
		// "When comparing attributes of type String, the case sensitivity
		// for String type attributes SHALL be determined by the attribute's
		// "caseExact" characteristic". A reference is case exact (RFC 7643
		// Section 2.3.7), and so is binary data.
		if !def.CaseExact && def.Type == "string" {
			a, e = strings.ToLower(a), strings.ToLower(e)
		}
		// RFC 7644 Section 5: "Before comparing or evaluating the uniqueness
		// of a "userName" or "password" attribute, service providers MUST use
		// the preparation, enforcement, and comparison of internationalized
		// strings (PRECIS) preparation and comparison rules". A value the
		// profile does not allow, such as part of a name, is compared as it
		// is.
		if def.Name == "userName" && def.Uniqueness == "server" {
			if key, err := userNameKey(a); err == nil {
				a = key
			}
			if key, err := userNameKey(e); err == nil {
				e = key
			}
		}
		return compareText(op, a, e), nil
	}
	switch op {
	case "eq":
		return order == 0, nil
	case "gt":
		return order > 0, nil
	case "ge":
		return order >= 0, nil
	case "lt":
		return order < 0, nil
	case "le":
		return order <= 0, nil
	}
	return false, nil
}

// compareText applies an operator to two strings: "For string attribute
// types, this is a lexicographical comparison".
func compareText(op, actual, expected string) bool {
	switch op {
	case "eq":
		return actual == expected
	case "co":
		return strings.Contains(actual, expected)
	case "sw":
		return strings.HasPrefix(actual, expected)
	case "ew":
		return strings.HasSuffix(actual, expected)
	case "gt":
		return actual > expected
	case "ge":
		return actual >= expected
	case "lt":
		return actual < expected
	case "le":
		return actual <= expected
	}
	return false
}
