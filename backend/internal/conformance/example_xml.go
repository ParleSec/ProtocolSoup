package conformance

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// An XML example part lists a document's attributes and child elements as
// members. A member's path is the part name, then element local names
// joined by dots, with "@" before an attribute name: "response.@ID",
// "response.Assertion.Subject". Namespace declarations are not members.

// xmlElement is one element of a parsed document and the bytes it occupies.
type xmlElement struct {
	name       string
	attributes []xml.Attr
	// raw[start:end] is the element exactly as it was sent.
	start, end int
	children   []*xmlElement
	// text is set when the element has character data other than white
	// space, so its content cannot be re-indented without changing it.
	text bool
}

// parseXML reads a well-formed document and returns its root element.
func parseXML(raw []byte) (*xmlElement, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var root *xmlElement
	var open []*xmlElement
	for {
		start := int(decoder.InputOffset())
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := token.(type) {
		case xml.StartElement:
			element := &xmlElement{name: t.Name.Local, start: start}
			for _, attribute := range t.Attr {
				if attribute.Name.Space == "xmlns" || (attribute.Name.Space == "" && attribute.Name.Local == "xmlns") {
					continue
				}
				element.attributes = append(element.attributes, attribute)
			}
			if len(open) > 0 {
				parent := open[len(open)-1]
				parent.children = append(parent.children, element)
			} else if root != nil {
				return nil, fmt.Errorf("document has more than one root element")
			} else {
				root = element
			}
			open = append(open, element)
		case xml.EndElement:
			open[len(open)-1].end = int(decoder.InputOffset())
			open = open[:len(open)-1]
		case xml.CharData:
			if len(open) > 0 && len(bytes.TrimSpace(t)) > 0 {
				open[len(open)-1].text = true
			}
		}
	}
	if root == nil {
		return nil, fmt.Errorf("document has no root element")
	}
	return root, nil
}

// xmlPart decodes one XML document into a part.
func xmlPart(name string, raw []byte, annotated map[string]struct{}) (ExamplePart, error) {
	root, err := parseXML(raw)
	if err != nil {
		return ExamplePart{}, fmt.Errorf("decode %s: %w", name, err)
	}
	members, err := xmlMembers(name, root, raw, annotated, true)
	if err != nil {
		return ExamplePart{}, fmt.Errorf("decode %s: %w", name, err)
	}
	var indented strings.Builder
	if prolog := bytes.TrimSpace(raw[:root.start]); len(prolog) > 0 {
		indented.Write(prolog)
		indented.WriteByte('\n')
	}
	indentXML(&indented, root, raw, 0)
	return ExamplePart{Name: name, JSON: string(raw), Indented: indented.String(), Members: members}, nil
}

// xmlMembers lists the attributes and child elements of element under
// prefix, in document order. Every member of the root is listed; below it a
// member is listed when a field annotates it or something inside it. An
// attribute's value is its text. An element's value is its bytes as sent,
// unless it holds other elements: such an element has no value of its own
// here, because the part shows it in full and its content is listed after it.
func xmlMembers(prefix string, element *xmlElement, raw []byte, annotated map[string]struct{}, all bool) ([]ExampleMember, error) {
	listed := func(path string) bool {
		if all {
			return true
		}
		_, ok := annotated[path]
		return ok || annotatesInside(annotated, path)
	}
	var members []ExampleMember
	for _, attribute := range element.attributes {
		if path := prefix + ".@" + attribute.Name.Local; listed(path) {
			members = append(members, ExampleMember{Path: path, Value: attribute.Value})
		}
	}
	seen := map[string]bool{}
	for _, child := range element.children {
		path := prefix + "." + child.name
		if !listed(path) {
			continue
		}
		// A path names a child by its element name alone, so it cannot
		// tell two children of the same name apart.
		if seen[child.name] {
			return nil, fmt.Errorf("%s has more than one <%s> child", prefix, child.name)
		}
		seen[child.name] = true
		member := ExampleMember{Path: path}
		if len(child.children) == 0 {
			member.Value = string(raw[child.start:child.end])
		}
		members = append(members, member)
		nested, err := xmlMembers(path, child, raw, annotated, false)
		if err != nil {
			return nil, err
		}
		members = append(members, nested...)
	}
	return members, nil
}

// indentXML writes element with each child element on its own line. It adds
// only line breaks and indentation between tags: an element with text, or
// with no child elements, is written exactly as it was sent.
func indentXML(out *strings.Builder, element *xmlElement, raw []byte, depth int) {
	pad := strings.Repeat("  ", depth)
	if element.text || len(element.children) == 0 {
		out.WriteString(pad)
		out.Write(raw[element.start:element.end])
		out.WriteByte('\n')
		return
	}
	first, last := element.children[0], element.children[len(element.children)-1]
	out.WriteString(pad)
	out.Write(bytes.TrimSpace(raw[element.start:first.start]))
	out.WriteByte('\n')
	for _, child := range element.children {
		indentXML(out, child, raw, depth+1)
	}
	out.WriteString(pad)
	out.Write(bytes.TrimSpace(raw[last.end:element.end]))
	out.WriteByte('\n')
}
