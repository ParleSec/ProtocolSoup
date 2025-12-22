package scim

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// FilterParser implements RFC 7644 Section 3.4.2.2 filter syntax
// Grammar:
//   filter     = attrExp / logExp / valuePath / *1"not" "(" filter ")"
//   logExp     = filter SP ("and" / "or") SP filter
//   attrExp    = attrPath SP compareOp SP compValue
//   valuePath  = attrPath "[" valFilter "]"
//   compareOp  = "eq" / "ne" / "co" / "sw" / "ew" / "gt" / "lt" / "ge" / "le" / "pr"

// TokenType represents a lexer token type
type TokenType int

const (
	TokenEOF TokenType = iota
	TokenIdent
	TokenString
	TokenNumber
	TokenBoolean
	TokenNull
	TokenLParen
	TokenRParen
	TokenLBracket
	TokenRBracket
	TokenDot
	TokenAnd
	TokenOr
	TokenNot
	TokenEq
	TokenNe
	TokenCo
	TokenSw
	TokenEw
	TokenGt
	TokenLt
	TokenGe
	TokenLe
	TokenPr
)

var tokenNames = map[TokenType]string{
	TokenEOF:      "EOF",
	TokenIdent:    "IDENT",
	TokenString:   "STRING",
	TokenNumber:   "NUMBER",
	TokenBoolean:  "BOOLEAN",
	TokenNull:     "NULL",
	TokenLParen:   "(",
	TokenRParen:   ")",
	TokenLBracket: "[",
	TokenRBracket: "]",
	TokenDot:      ".",
	TokenAnd:      "and",
	TokenOr:       "or",
	TokenNot:      "not",
	TokenEq:       "eq",
	TokenNe:       "ne",
	TokenCo:       "co",
	TokenSw:       "sw",
	TokenEw:       "ew",
	TokenGt:       "gt",
	TokenLt:       "lt",
	TokenGe:       "ge",
	TokenLe:       "le",
	TokenPr:       "pr",
}

// Token represents a lexer token
type Token struct {
	Type  TokenType
	Value string
}

func (t Token) String() string {
	return fmt.Sprintf("%s(%q)", tokenNames[t.Type], t.Value)
}

// Lexer tokenizes SCIM filter expressions
type Lexer struct {
	input string
	pos   int
}

// NewLexer creates a new lexer for the input string
func NewLexer(input string) *Lexer {
	return &Lexer{input: input}
}

// NextToken returns the next token from the input
func (l *Lexer) NextToken() Token {
	l.skipWhitespace()

	if l.pos >= len(l.input) {
		return Token{Type: TokenEOF}
	}

	ch := l.input[l.pos]

	// Single character tokens
	switch ch {
	case '(':
		l.pos++
		return Token{Type: TokenLParen, Value: "("}
	case ')':
		l.pos++
		return Token{Type: TokenRParen, Value: ")"}
	case '[':
		l.pos++
		return Token{Type: TokenLBracket, Value: "["}
	case ']':
		l.pos++
		return Token{Type: TokenRBracket, Value: "]"}
	case '.':
		l.pos++
		return Token{Type: TokenDot, Value: "."}
	case '"':
		return l.readString()
	}

	// Numbers
	if unicode.IsDigit(rune(ch)) || ch == '-' {
		return l.readNumber()
	}

	// Identifiers and keywords
	if unicode.IsLetter(rune(ch)) || ch == '_' {
		return l.readIdentifier()
	}

	// Unknown character
	l.pos++
	return Token{Type: TokenIdent, Value: string(ch)}
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.input) && unicode.IsSpace(rune(l.input[l.pos])) {
		l.pos++
	}
}

func (l *Lexer) readString() Token {
	l.pos++ // Skip opening quote
	start := l.pos
	
	for l.pos < len(l.input) && l.input[l.pos] != '"' {
		if l.input[l.pos] == '\\' && l.pos+1 < len(l.input) {
			l.pos += 2 // Skip escaped character
		} else {
			l.pos++
		}
	}
	
	value := l.input[start:l.pos]
	if l.pos < len(l.input) {
		l.pos++ // Skip closing quote
	}
	
	// Unescape the string
	value = unescapeString(value)
	return Token{Type: TokenString, Value: value}
}

func (l *Lexer) readNumber() Token {
	start := l.pos
	if l.input[l.pos] == '-' {
		l.pos++
	}
	for l.pos < len(l.input) && (unicode.IsDigit(rune(l.input[l.pos])) || l.input[l.pos] == '.') {
		l.pos++
	}
	return Token{Type: TokenNumber, Value: l.input[start:l.pos]}
}

func (l *Lexer) readIdentifier() Token {
	start := l.pos
	for l.pos < len(l.input) {
		ch := rune(l.input[l.pos])
		if unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_' || ch == ':' || ch == '-' {
			l.pos++
		} else {
			break
		}
	}
	value := l.input[start:l.pos]
	
	// Check for keywords
	lower := strings.ToLower(value)
	switch lower {
	case "and":
		return Token{Type: TokenAnd, Value: value}
	case "or":
		return Token{Type: TokenOr, Value: value}
	case "not":
		return Token{Type: TokenNot, Value: value}
	case "eq":
		return Token{Type: TokenEq, Value: value}
	case "ne":
		return Token{Type: TokenNe, Value: value}
	case "co":
		return Token{Type: TokenCo, Value: value}
	case "sw":
		return Token{Type: TokenSw, Value: value}
	case "ew":
		return Token{Type: TokenEw, Value: value}
	case "gt":
		return Token{Type: TokenGt, Value: value}
	case "lt":
		return Token{Type: TokenLt, Value: value}
	case "ge":
		return Token{Type: TokenGe, Value: value}
	case "le":
		return Token{Type: TokenLe, Value: value}
	case "pr":
		return Token{Type: TokenPr, Value: value}
	case "true", "false":
		return Token{Type: TokenBoolean, Value: lower}
	case "null":
		return Token{Type: TokenNull, Value: "null"}
	}
	
	return Token{Type: TokenIdent, Value: value}
}

func unescapeString(s string) string {
	s = strings.ReplaceAll(s, "\\\"", "\"")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\t", "\t")
	return s
}

// ================== AST Nodes ==================

// FilterNode represents a node in the filter AST
type FilterNode interface {
	filterNode()
	String() string
}

// AttrExpr represents an attribute comparison expression
type AttrExpr struct {
	Path     *AttrPath
	Operator string
	Value    interface{}
}

func (AttrExpr) filterNode() {}
func (e AttrExpr) String() string {
	if e.Operator == "pr" {
		return fmt.Sprintf("%s pr", e.Path)
	}
	return fmt.Sprintf("%s %s %v", e.Path, e.Operator, e.Value)
}

// AttrPath represents an attribute path (e.g., "name.familyName")
type AttrPath struct {
	Schema    string   // Optional schema URN
	Attribute string   // Root attribute
	SubAttr   string   // Optional sub-attribute
	ValuePath *Filter  // Optional value filter for multi-valued attributes
}

func (p AttrPath) String() string {
	var sb strings.Builder
	if p.Schema != "" {
		sb.WriteString(p.Schema)
		sb.WriteString(":")
	}
	sb.WriteString(p.Attribute)
	if p.SubAttr != "" {
		sb.WriteString(".")
		sb.WriteString(p.SubAttr)
	}
	if p.ValuePath != nil {
		sb.WriteString("[")
		sb.WriteString(p.ValuePath.String())
		sb.WriteString("]")
	}
	return sb.String()
}

// LogExpr represents a logical expression (AND/OR)
type LogExpr struct {
	Left     FilterNode
	Operator string // "and" or "or"
	Right    FilterNode
}

func (LogExpr) filterNode() {}
func (e LogExpr) String() string {
	return fmt.Sprintf("(%s %s %s)", e.Left, e.Operator, e.Right)
}

// NotExpr represents a NOT expression
type NotExpr struct {
	Expr FilterNode
}

func (NotExpr) filterNode() {}
func (e NotExpr) String() string {
	return fmt.Sprintf("not (%s)", e.Expr)
}

// Filter represents a parsed SCIM filter
type Filter struct {
	Root FilterNode
}

func (f Filter) String() string {
	if f.Root == nil {
		return ""
	}
	return f.Root.String()
}

// ================== Parser ==================

// Parser parses SCIM filter expressions
type Parser struct {
	lexer   *Lexer
	current Token
	peek    Token
}

// NewParser creates a new parser for the input
func NewParser(input string) *Parser {
	p := &Parser{lexer: NewLexer(input)}
	p.nextToken()
	p.nextToken()
	return p
}

func (p *Parser) nextToken() {
	p.current = p.peek
	p.peek = p.lexer.NextToken()
}

// Parse parses the filter expression
func (p *Parser) Parse() (*Filter, error) {
	if p.current.Type == TokenEOF {
		return &Filter{}, nil
	}
	
	node, err := p.parseExpression(0)
	if err != nil {
		return nil, err
	}
	
	return &Filter{Root: node}, nil
}

// Operator precedence
const (
	precLowest = iota
	precOr
	precAnd
	precNot
	precCompare
)

func (p *Parser) parseExpression(precedence int) (FilterNode, error) {
	var left FilterNode
	var err error

	// Handle NOT prefix
	if p.current.Type == TokenNot {
		p.nextToken()
		if p.current.Type != TokenLParen {
			return nil, fmt.Errorf("expected '(' after 'not', got %s", p.current)
		}
		p.nextToken()
		inner, err := p.parseExpression(precLowest)
		if err != nil {
			return nil, err
		}
		if p.current.Type != TokenRParen {
			return nil, fmt.Errorf("expected ')', got %s", p.current)
		}
		p.nextToken()
		left = &NotExpr{Expr: inner}
	} else if p.current.Type == TokenLParen {
		// Grouped expression
		p.nextToken()
		left, err = p.parseExpression(precLowest)
		if err != nil {
			return nil, err
		}
		if p.current.Type != TokenRParen {
			return nil, fmt.Errorf("expected ')', got %s", p.current)
		}
		p.nextToken()
	} else {
		// Attribute expression
		left, err = p.parseAttrExpr()
		if err != nil {
			return nil, err
		}
	}

	// Parse binary operators (AND/OR)
	for {
		var opPrec int
		var op string
		
		switch p.current.Type {
		case TokenAnd:
			opPrec = precAnd
			op = "and"
		case TokenOr:
			opPrec = precOr
			op = "or"
		default:
			return left, nil
		}
		
		if opPrec <= precedence {
			return left, nil
		}
		
		p.nextToken()
		right, err := p.parseExpression(opPrec)
		if err != nil {
			return nil, err
		}
		
		left = &LogExpr{Left: left, Operator: op, Right: right}
	}
}

func (p *Parser) parseAttrExpr() (FilterNode, error) {
	path, err := p.parseAttrPath()
	if err != nil {
		return nil, err
	}

	// Check for presence operator (no value)
	if p.current.Type == TokenPr {
		p.nextToken()
		return &AttrExpr{Path: path, Operator: "pr"}, nil
	}

	// Parse comparison operator
	op, err := p.parseCompareOp()
	if err != nil {
		return nil, err
	}

	// Parse value
	value, err := p.parseValue()
	if err != nil {
		return nil, err
	}

	return &AttrExpr{Path: path, Operator: op, Value: value}, nil
}

func (p *Parser) parseAttrPath() (*AttrPath, error) {
	if p.current.Type != TokenIdent {
		return nil, fmt.Errorf("expected attribute name, got %s", p.current)
	}

	path := &AttrPath{}
	name := p.current.Value
	p.nextToken()

	// Check for schema URN prefix (contains :)
	if strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 && strings.HasPrefix(parts[0], "urn") {
			// This is a schema URN, but we need more tokens
			// Reconstruct the full URN
			path.Schema = name
			// The attribute name follows
			if p.current.Type == TokenIdent {
				path.Attribute = p.current.Value
				p.nextToken()
			}
		} else {
			path.Attribute = name
		}
	} else {
		path.Attribute = name
	}

	// Check for sub-attribute
	if p.current.Type == TokenDot {
		p.nextToken()
		if p.current.Type != TokenIdent {
			return nil, fmt.Errorf("expected sub-attribute name, got %s", p.current)
		}
		path.SubAttr = p.current.Value
		p.nextToken()
	}

	// Check for value filter
	if p.current.Type == TokenLBracket {
		p.nextToken()
		filter, err := p.parseExpression(precLowest)
		if err != nil {
			return nil, err
		}
		path.ValuePath = &Filter{Root: filter}
		if p.current.Type != TokenRBracket {
			return nil, fmt.Errorf("expected ']', got %s", p.current)
		}
		p.nextToken()
		
		// Check for sub-attribute after value path
		if p.current.Type == TokenDot {
			p.nextToken()
			if p.current.Type != TokenIdent {
				return nil, fmt.Errorf("expected sub-attribute name, got %s", p.current)
			}
			path.SubAttr = p.current.Value
			p.nextToken()
		}
	}

	return path, nil
}

func (p *Parser) parseCompareOp() (string, error) {
	switch p.current.Type {
	case TokenEq:
		p.nextToken()
		return "eq", nil
	case TokenNe:
		p.nextToken()
		return "ne", nil
	case TokenCo:
		p.nextToken()
		return "co", nil
	case TokenSw:
		p.nextToken()
		return "sw", nil
	case TokenEw:
		p.nextToken()
		return "ew", nil
	case TokenGt:
		p.nextToken()
		return "gt", nil
	case TokenLt:
		p.nextToken()
		return "lt", nil
	case TokenGe:
		p.nextToken()
		return "ge", nil
	case TokenLe:
		p.nextToken()
		return "le", nil
	default:
		return "", fmt.Errorf("expected comparison operator, got %s", p.current)
	}
}

func (p *Parser) parseValue() (interface{}, error) {
	switch p.current.Type {
	case TokenString:
		value := p.current.Value
		p.nextToken()
		return value, nil
	case TokenNumber:
		value := p.current.Value
		p.nextToken()
		// Try to parse as int first, then float
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i, nil
		}
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f, nil
		}
		return value, nil
	case TokenBoolean:
		value := p.current.Value == "true"
		p.nextToken()
		return value, nil
	case TokenNull:
		p.nextToken()
		return nil, nil
	default:
		return nil, fmt.Errorf("expected value, got %s", p.current)
	}
}

// ================== SQL Translation ==================

// FilterToSQL converts a parsed filter to SQL WHERE clause
type SQLTranslator struct {
	resourceType string
	params       []interface{}
	paramIndex   int
}

// NewSQLTranslator creates a new SQL translator
func NewSQLTranslator(resourceType string) *SQLTranslator {
	return &SQLTranslator{
		resourceType: resourceType,
		params:       make([]interface{}, 0),
		paramIndex:   0,
	}
}

// Translate converts a filter to SQL
func (t *SQLTranslator) Translate(filter *Filter) (string, []interface{}, error) {
	if filter == nil || filter.Root == nil {
		return "", nil, nil
	}
	
	sql, err := t.translateNode(filter.Root)
	if err != nil {
		return "", nil, err
	}
	
	return sql, t.params, nil
}

func (t *SQLTranslator) translateNode(node FilterNode) (string, error) {
	switch n := node.(type) {
	case *AttrExpr:
		return t.translateAttrExpr(n)
	case *LogExpr:
		return t.translateLogExpr(n)
	case *NotExpr:
		return t.translateNotExpr(n)
	default:
		return "", fmt.Errorf("unknown node type: %T", node)
	}
}

func (t *SQLTranslator) translateAttrExpr(expr *AttrExpr) (string, error) {
	column := t.attrToColumn(expr.Path)
	
	// Handle presence check
	if expr.Operator == "pr" {
		return fmt.Sprintf("(%s IS NOT NULL AND %s != '')", column, column), nil
	}

	t.paramIndex++
	placeholder := "?"

	switch expr.Operator {
	case "eq":
		t.params = append(t.params, expr.Value)
		return fmt.Sprintf("%s = %s", column, placeholder), nil
	case "ne":
		t.params = append(t.params, expr.Value)
		return fmt.Sprintf("%s != %s", column, placeholder), nil
	case "co":
		t.params = append(t.params, fmt.Sprintf("%%%v%%", expr.Value))
		return fmt.Sprintf("%s LIKE %s", column, placeholder), nil
	case "sw":
		t.params = append(t.params, fmt.Sprintf("%v%%", expr.Value))
		return fmt.Sprintf("%s LIKE %s", column, placeholder), nil
	case "ew":
		t.params = append(t.params, fmt.Sprintf("%%%v", expr.Value))
		return fmt.Sprintf("%s LIKE %s", column, placeholder), nil
	case "gt":
		t.params = append(t.params, expr.Value)
		return fmt.Sprintf("%s > %s", column, placeholder), nil
	case "lt":
		t.params = append(t.params, expr.Value)
		return fmt.Sprintf("%s < %s", column, placeholder), nil
	case "ge":
		t.params = append(t.params, expr.Value)
		return fmt.Sprintf("%s >= %s", column, placeholder), nil
	case "le":
		t.params = append(t.params, expr.Value)
		return fmt.Sprintf("%s <= %s", column, placeholder), nil
	default:
		return "", fmt.Errorf("unsupported operator: %s", expr.Operator)
	}
}

func (t *SQLTranslator) translateLogExpr(expr *LogExpr) (string, error) {
	left, err := t.translateNode(expr.Left)
	if err != nil {
		return "", err
	}
	
	right, err := t.translateNode(expr.Right)
	if err != nil {
		return "", err
	}
	
	op := strings.ToUpper(expr.Operator)
	return fmt.Sprintf("(%s %s %s)", left, op, right), nil
}

func (t *SQLTranslator) translateNotExpr(expr *NotExpr) (string, error) {
	inner, err := t.translateNode(expr.Expr)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("NOT (%s)", inner), nil
}

// attrToColumn maps SCIM attributes to database columns/JSON paths
func (t *SQLTranslator) attrToColumn(path *AttrPath) string {
	attr := strings.ToLower(path.Attribute)
	subAttr := strings.ToLower(path.SubAttr)
	
	// Direct column mappings
	switch attr {
	case "id":
		return "id"
	case "externalid":
		return "external_id"
	case "username":
		return "user_name"
	case "displayname":
		return "display_name"
	case "meta":
		switch subAttr {
		case "created":
			return "created_at"
		case "lastmodified":
			return "updated_at"
		default:
			return fmt.Sprintf("json_extract(data, '$.meta.%s')", subAttr)
		}
	}

	// JSON path for other attributes
	jsonPath := "$." + path.Attribute
	if path.SubAttr != "" {
		jsonPath += "." + path.SubAttr
	}
	
	return fmt.Sprintf("json_extract(data, '%s')", jsonPath)
}

// ParseFilter parses a SCIM filter string
func ParseFilter(input string) (*Filter, error) {
	if input == "" {
		return nil, nil
	}
	parser := NewParser(input)
	return parser.Parse()
}

// FilterToSQLWhere converts a filter string to SQL WHERE clause
func FilterToSQLWhere(filter string, resourceType string) (string, []interface{}, error) {
	if filter == "" {
		return "", nil, nil
	}
	
	parsed, err := ParseFilter(filter)
	if err != nil {
		return "", nil, ErrInvalidFilter(err.Error())
	}
	
	translator := NewSQLTranslator(resourceType)
	sql, params, err := translator.Translate(parsed)
	if err != nil {
		return "", nil, ErrInvalidFilter(err.Error())
	}
	
	return sql, params, nil
}

// ================== JSON Path Evaluation ==================

// Regular expressions for common filter patterns
var (
	simpleEqRegex = regexp.MustCompile(`^(\w+)\s+eq\s+"([^"]*)"$`)
	simpleSwRegex = regexp.MustCompile(`^(\w+)\s+sw\s+"([^"]*)"$`)
)

// QuickFilter provides fast path for simple filter patterns
func QuickFilter(filter string) (attr string, op string, value string, ok bool) {
	filter = strings.TrimSpace(filter)
	
	if matches := simpleEqRegex.FindStringSubmatch(filter); len(matches) == 3 {
		return matches[1], "eq", matches[2], true
	}
	if matches := simpleSwRegex.FindStringSubmatch(filter); len(matches) == 3 {
		return matches[1], "sw", matches[2], true
	}
	
	return "", "", "", false
}

