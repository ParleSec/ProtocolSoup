package scim

import "strings"

// The attribute definitions the service provider acts on are the ones it
// serves at /Schemas (discovery.go), so a client that reads a characteristic
// there sees the behaviour that characteristic promises: caseExact decides
// how a filter compares, returned decides what a response carries, and
// mutability decides what PATCH may change.

// commonAttributes are the attributes of RFC 7643 Section 3.1, which "are
// considered to be part of every base resource schema and do not use their
// own "schemas" URI", and the "schemas" attribute of Section 3.
var commonAttributes = []Attribute{
	// "All representations of SCIM schemas MUST include a non-empty array
	// with value(s) of the URIs supported by that representation."
	{Name: "schemas", Type: "reference", MultiValued: true, Required: true, CaseExact: true, Mutability: "readWrite", Returned: "always"},
	// id: 'The attribute characteristics are "caseExact" as "true", a
	// mutability of "readOnly", and a "returned" characteristic of "always".'
	{Name: "id", Type: "string", CaseExact: true, Mutability: "readOnly", Returned: "always"},
	// externalId: 'This attribute has "caseExact" as "true" and a mutability
	// of "readWrite".'
	{Name: "externalId", Type: "string", CaseExact: true, Mutability: "readWrite", Returned: "default"},
	// meta: 'All "meta" sub-attributes are assigned by the service provider
	// (have a "mutability" of "readOnly"), and all of these sub-attributes
	// have a "returned" characteristic of "default".'
	{Name: "meta", Type: "complex", Mutability: "readOnly", Returned: "default", SubAttributes: []Attribute{
		{Name: "resourceType", Type: "string", CaseExact: true, Mutability: "readOnly", Returned: "default"},
		{Name: "created", Type: "dateTime", Mutability: "readOnly", Returned: "default"},
		{Name: "lastModified", Type: "dateTime", Mutability: "readOnly", Returned: "default"},
		{Name: "location", Type: "reference", CaseExact: true, Mutability: "readOnly", Returned: "default"},
		{Name: "version", Type: "string", CaseExact: true, Mutability: "readOnly", Returned: "default"},
	}},
}

// resourceSchema is the set of attributes one resource type defines: the
// common attributes, its core schema and its schema extensions.
type resourceSchema struct {
	resourceType string
	core         *Schema
	extensions   []*Schema
}

var (
	userResourceSchema  = &resourceSchema{resourceType: "User", core: GetSchema("", SchemaURNUser), extensions: []*Schema{GetSchema("", SchemaURNEnterpriseUser)}}
	groupResourceSchema = &resourceSchema{resourceType: "Group", core: GetSchema("", SchemaURNGroup)}
)

// schemaOf returns the schema of a resource representation, from its
// meta.resourceType.
func schemaOf(resource map[string]interface{}) *resourceSchema {
	meta, _ := resource["meta"].(map[string]interface{})
	if meta["resourceType"] == "Group" {
		return groupResourceSchema
	}
	return userResourceSchema
}

// findAttribute finds an attribute by name. RFC 7643 Section 2.1: "Attribute
// names are case insensitive".
func findAttribute(attributes []Attribute, name string) *Attribute {
	for i := range attributes {
		if strings.EqualFold(attributes[i].Name, name) {
			return &attributes[i]
		}
	}
	return nil
}

// located is an attribute definition and the schema extension it belongs to.
// extension is "" for a common or core attribute, which sits at the top level
// of the resource; an extended attribute sits under its extension's URI (RFC
// 7643 Section 3).
type located struct {
	def       *Attribute
	extension string
}

// locate resolves the attribute a path names, without its sub-attribute. A
// path may carry the schema URI: RFC 7644 Section 3.10 has clients "MAY omit
// core schema attribute URN prefixes".
func (s *resourceSchema) locate(path attrPath) (located, bool) {
	if path.Schema != "" {
		if strings.EqualFold(path.Schema, s.core.ID) {
			if def := findAttribute(s.core.Attributes, path.Name); def != nil {
				return located{def: def}, true
			}
			return located{}, false
		}
		for _, extension := range s.extensions {
			if strings.EqualFold(path.Schema, extension.ID) {
				if def := findAttribute(extension.Attributes, path.Name); def != nil {
					return located{def: def, extension: extension.ID}, true
				}
			}
		}
		return located{}, false
	}
	if def := findAttribute(commonAttributes, path.Name); def != nil {
		return located{def: def}, true
	}
	if def := findAttribute(s.core.Attributes, path.Name); def != nil {
		return located{def: def}, true
	}
	for _, extension := range s.extensions {
		if def := findAttribute(extension.Attributes, path.Name); def != nil {
			return located{def: def, extension: extension.ID}, true
		}
	}
	return located{}, false
}

// container returns the object that holds an attribute: the resource, or the
// object under the extension's URI. create adds that object when it is
// missing.
func (l located) container(resource map[string]interface{}, create bool) map[string]interface{} {
	if l.extension == "" {
		return resource
	}
	if object, ok := resource[l.extension].(map[string]interface{}); ok {
		return object
	}
	if !create {
		return nil
	}
	object := map[string]interface{}{}
	resource[l.extension] = object
	return object
}

// assigned reports whether a JSON value counts as a value. RFC 7643 Section
// 2.5: "Unassigned attributes, the null value, or an empty array (in the case
// of a multi-valued attribute) SHALL be considered to be equivalent in
// "state"."
func assigned(value interface{}) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return typed != ""
	case []interface{}:
		return len(typed) > 0
	case map[string]interface{}:
		return len(typed) > 0
	default:
		return true
	}
}

// leaves returns the definition and the assigned values a path selects from a
// resource. A multi-valued attribute yields each of its values. A complex
// attribute named without a sub-attribute yields its "value" sub-attribute
// when it has one (RFC 7643 Section 2.4), and otherwise the complex values
// themselves. The definition is nil when the resource type does not define
// the attribute: RFC 7644 Section 3.4.2.1 has the service provider "treat the
// attribute as if there is no attribute value".
func (s *resourceSchema) leaves(resource map[string]interface{}, path attrPath) (*Attribute, []interface{}) {
	found, ok := s.locate(path)
	if !ok {
		return nil, nil
	}
	return subLeaves(found.def, found.container(resource, false)[found.def.Name], path.Sub)
}

// subLeaves is leaves below an attribute whose value is already in hand.
func subLeaves(def *Attribute, raw interface{}, sub string) (*Attribute, []interface{}) {
	elements, _ := raw.([]interface{})
	if !def.MultiValued && raw != nil {
		elements = []interface{}{raw}
	}
	leaf := def
	if def.Type == "complex" {
		if sub == "" {
			sub = "value"
			if findAttribute(def.SubAttributes, sub) == nil {
				var nodes []interface{}
				for _, element := range elements {
					if assigned(element) {
						nodes = append(nodes, element)
					}
				}
				return def, nodes
			}
		}
		leaf = findAttribute(def.SubAttributes, sub)
		if leaf == nil {
			return nil, nil
		}
		var values []interface{}
		for _, element := range elements {
			object, _ := element.(map[string]interface{})
			if value := object[leaf.Name]; assigned(value) {
				values = append(values, value)
			}
		}
		return leaf, values
	}
	if sub != "" {
		return nil, nil
	}
	var values []interface{}
	for _, element := range elements {
		if assigned(element) {
			values = append(values, element)
		}
	}
	return leaf, values
}
