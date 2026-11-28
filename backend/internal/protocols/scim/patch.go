package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
)

// PATCH (RFC 7644 Section 3.5.2). The operations are applied to a decoded
// copy of the stored resource, with the attribute definitions of schema.go
// deciding what each operation may do. The caller stores the result only when
// every operation succeeded: "A PATCH request, regardless of the number of
// operations, SHALL be treated as atomic. If a single operation encounters an
// error condition, the original SCIM resource MUST be restored, and a failure
// status SHALL be returned."

// patchOperation is one member of "Operations".
type patchOperation struct {
	op       string
	path     string
	hasPath  bool
	value    interface{}
	hasValue bool
}

// parsePatchRequest reads the body of a PATCH request.
func parsePatchRequest(body []byte) ([]patchOperation, *SCIMError) {
	var request struct {
		Schemas    []string                     `json:"schemas"`
		Operations []map[string]json.RawMessage `json:"Operations"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, ErrInvalidSyntax("Invalid JSON: " + err.Error())
	}
	// 'The body of each request MUST contain the "schemas" attribute with the
	// URI value of "urn:ietf:params:scim:api:messages:2.0:PatchOp".'
	if scimErr := checkSchemas(request.Schemas, SchemaURNPatchOp); scimErr != nil {
		return nil, scimErr
	}
	// 'The body of an HTTP PATCH request MUST contain the attribute
	// "Operations", whose value is an array of one or more PATCH operations.'
	if len(request.Operations) == 0 {
		return nil, ErrInvalidSyntax("Operations must be an array of one or more PATCH operations")
	}
	operations := make([]patchOperation, 0, len(request.Operations))
	for i, raw := range request.Operations {
		var operation patchOperation
		// 'Each PATCH operation object MUST have exactly one "op" member,
		// whose value indicates the operation to perform and MAY be one of
		// "add", "remove", or "replace".'
		if err := json.Unmarshal(raw["op"], &operation.op); err != nil || (operation.op != "add" && operation.op != "remove" && operation.op != "replace") {
			return nil, ErrInvalidSyntax(fmt.Sprintf("operation %d: op must be add, remove or replace", i))
		}
		if rawPath, present := raw["path"]; present {
			if err := json.Unmarshal(rawPath, &operation.path); err != nil {
				return nil, ErrInvalidPath(fmt.Sprintf("operation %d: path must be a string", i))
			}
			operation.hasPath = true
		}
		if rawValue, present := raw["value"]; present {
			if err := json.Unmarshal(rawValue, &operation.value); err != nil {
				return nil, ErrInvalidSyntax(fmt.Sprintf("operation %d: %v", i, err))
			}
			operation.hasValue = true
		}
		operations = append(operations, operation)
	}
	return operations, nil
}

// applyPatch applies operations to resource, in place.
func applyPatch(resource map[string]interface{}, schema *resourceSchema, operations []patchOperation) *SCIMError {
	for i, operation := range operations {
		if scimErr := applyPatchOperation(resource, schema, operation); scimErr != nil {
			scimErr.Detail = fmt.Sprintf("operation %d (%s): %s", i, operation.op, scimErr.Detail)
			return scimErr
		}
	}
	// 'Clients MAY implicitly modify the "schemas" attribute by adding (or
	// replacing) an attribute with its fully qualified name, including schema
	// URN.' "schemas" names an extension exactly when the resource carries
	// attributes of it.
	schemas := []interface{}{schema.core.ID}
	for _, extension := range schema.extensions {
		if object, ok := resource[extension.ID].(map[string]interface{}); ok && len(object) > 0 {
			schemas = append(schemas, extension.ID)
		} else {
			delete(resource, extension.ID)
		}
	}
	resource["schemas"] = schemas
	return nil
}

func applyPatchOperation(resource map[string]interface{}, schema *resourceSchema, operation patchOperation) *SCIMError {
	if operation.op != "remove" && !operation.hasValue {
		// add: 'The operation MUST contain a "value" member whose content
		// specifies the value to be added.'
		return ErrInvalidValue("the operation has no value")
	}
	if !operation.hasPath {
		if operation.op == "remove" {
			// 'If "path" is unspecified, the operation fails with HTTP status
			// code 400 and a "scimType" error code of "noTarget".'
			return ErrNoTarget("a remove operation needs a path")
		}
		// 'If omitted, the target location is assumed to be the resource
		// itself. The "value" parameter contains a set of attributes to be
		// added to the resource.'
		attributes, ok := operation.value.(map[string]interface{})
		if !ok {
			return ErrInvalidValue("with no path, the value must be an object of attributes")
		}
		for name, value := range attributes {
			// An extension's attributes may come as one object under its URI.
			if extension := schema.extension(name); extension != nil {
				members, isObject := value.(map[string]interface{})
				if !isObject {
					return ErrInvalidValue(fmt.Sprintf("the value of %s must be an object", name))
				}
				for member, memberValue := range members {
					if scimErr := setAttribute(resource, schema, patchPath{Attr: attrPath{Schema: extension.ID, Name: member}}, memberValue, operation.op); scimErr != nil {
						return scimErr
					}
				}
				continue
			}
			path, err := parseAttrPath(name)
			if err != nil {
				return ErrInvalidValue(err.Error())
			}
			if scimErr := setAttribute(resource, schema, patchPath{Attr: path}, value, operation.op); scimErr != nil {
				return scimErr
			}
		}
		return nil
	}

	path, err := ParsePatchPath(operation.path)
	if err != nil {
		return ErrInvalidPath(err.Error())
	}
	if operation.op == "remove" {
		return removeAttribute(resource, schema, path)
	}
	return setAttribute(resource, schema, path, operation.value, operation.op)
}

// extension returns the schema extension a URI names, or nil.
func (s *resourceSchema) extension(uri string) *Schema {
	for _, extension := range s.extensions {
		if strings.EqualFold(extension.ID, uri) {
			return extension
		}
	}
	return nil
}

// target resolves the attribute a PATCH path names and checks that a client
// may change it. 'Each operation against an attribute MUST be compatible with
// the attribute's mutability and schema as defined in Sections 2.2 and 2.3 of
// [RFC7643]. For example, a client MUST NOT modify an attribute that has
// mutability "readOnly" or "immutable".'
func target(schema *resourceSchema, path patchPath) (located, *Attribute, *SCIMError) {
	found, ok := schema.locate(path.Attr)
	if !ok {
		return found, nil, ErrInvalidPath(fmt.Sprintf("%s is not an attribute of the %s resource type", path.Attr, schema.resourceType))
	}
	if found.def.Mutability == "readOnly" {
		return found, nil, ErrMutability(found.def.Name)
	}
	name := path.Attr.Sub
	if path.Filter != nil {
		if !found.def.MultiValued || found.def.Type != "complex" {
			return found, nil, ErrInvalidPath(fmt.Sprintf("%s is not a multi-valued complex attribute, so its path takes no value filter", found.def.Name))
		}
		name = path.Sub
	}
	if name == "" {
		return found, nil, nil
	}
	sub := findAttribute(found.def.SubAttributes, name)
	if sub == nil {
		return found, nil, ErrInvalidPath(fmt.Sprintf("%s has no sub-attribute %s", found.def.Name, name))
	}
	if sub.Mutability == "readOnly" {
		return found, nil, ErrMutability(found.def.Name + "." + sub.Name)
	}
	return found, sub, nil
}

// matching returns the indexes of the values of a multi-valued complex
// attribute that a value filter selects.
func matching(def *Attribute, values []interface{}, filter filterNode) ([]int, *SCIMError) {
	var indexes []int
	for i, value := range values {
		object, _ := value.(map[string]interface{})
		ok, err := matchValue(filter, def, object)
		if err != nil {
			return nil, ErrInvalidFilter(err.Error())
		}
		if ok {
			indexes = append(indexes, i)
		}
	}
	return indexes, nil
}

// setAttribute performs an add or a replace (Sections 3.5.2.1 and 3.5.2.3).
func setAttribute(resource map[string]interface{}, schema *resourceSchema, path patchPath, value interface{}, op string) *SCIMError {
	found, sub, scimErr := target(schema, path)
	if scimErr != nil {
		return scimErr
	}
	def := found.def
	container := found.container(resource, true)
	current := container[def.Name]

	// A sub-attribute of selected values, or of every value.
	if sub != nil {
		checked, scimErr := checkValue(sub, value, def.Name+"."+sub.Name)
		if scimErr != nil {
			return scimErr
		}
		if !def.MultiValued {
			object, _ := current.(map[string]interface{})
			if object == nil {
				object = map[string]interface{}{}
			}
			if scimErr := immutable(sub, object[sub.Name], checked, def.Name+"."+sub.Name); scimErr != nil {
				return scimErr
			}
			object[sub.Name] = checked
			container[def.Name] = object
			return nil
		}
		values, _ := current.([]interface{})
		indexes := make([]int, len(values))
		for i := range values {
			indexes[i] = i
		}
		if path.Filter != nil {
			if indexes, scimErr = matching(def, values, path.Filter); scimErr != nil {
				return scimErr
			}
		}
		if len(indexes) == 0 {
			// 'If the target location is a multi-valued attribute for which a
			// value selection filter ("valuePath") has been supplied and no
			// record match was made, the service provider SHALL indicate
			// failure by returning HTTP status code 400 and a "scimType" error
			// code of "noTarget".'
			return ErrNoTarget(fmt.Sprintf("no value of %s matches the path", def.Name))
		}
		for _, i := range indexes {
			object, _ := values[i].(map[string]interface{})
			if scimErr := immutable(sub, object[sub.Name], checked, def.Name+"."+sub.Name); scimErr != nil {
				return scimErr
			}
			object[sub.Name] = checked
		}
		container[def.Name] = onePrimary(values, indexes)
		return nil
	}

	// Selected values replaced whole.
	if path.Filter != nil {
		values, _ := current.([]interface{})
		indexes, scimErr := matching(def, values, path.Filter)
		if scimErr != nil {
			return scimErr
		}
		if len(indexes) == 0 {
			return ErrNoTarget(fmt.Sprintf("no value of %s matches the path", def.Name))
		}
		one := *def
		one.MultiValued = false
		checked, scimErr := checkValue(&one, value, def.Name)
		if scimErr != nil {
			return scimErr
		}
		// "all matching record values SHALL be replaced."
		for _, i := range indexes {
			values[i] = deepCopy(checked)
		}
		container[def.Name] = onePrimary(values, indexes)
		return nil
	}

	checked, scimErr := checkValue(def, value, def.Name)
	if scimErr != nil {
		return scimErr
	}
	if scimErr := immutable(def, current, checked, def.Name); scimErr != nil {
		return scimErr
	}
	switch {
	case def.MultiValued && op == "add":
		// "If the target location specifies a multi-valued attribute, a new
		// value is added to the attribute." A value already there is left as
		// it is: "If the target location already contains the value
		// specified, no changes SHOULD be made to the resource".
		values, _ := current.([]interface{})
		var touched []int
		for _, added := range checked.([]interface{}) {
			at := indexOfValue(def, values, added)
			if at < 0 {
				values = append(values, added)
				at = len(values) - 1
			} else if object, isObject := values[at].(map[string]interface{}); isObject {
				for name, member := range added.(map[string]interface{}) {
					object[name] = member
				}
			}
			touched = append(touched, at)
		}
		container[def.Name] = onePrimary(values, touched)
	case def.MultiValued:
		// replace: "If the target location is a multi-valued attribute and no
		// filter is specified, the attribute and all values are replaced."
		values := checked.([]interface{})
		touched := make([]int, len(values))
		for i := range values {
			touched[i] = i
		}
		container[def.Name] = onePrimary(values, touched)
	case def.Type == "complex":
		// "If the target location specifies a complex attribute, a set of
		// sub-attributes SHALL be specified in the "value" parameter, which
		// replaces any existing values or adds where an attribute did not
		// previously exist. Sub-attributes that are not specified in the
		// "value" parameter are left unchanged."
		object, _ := current.(map[string]interface{})
		if object == nil {
			object = map[string]interface{}{}
		}
		for name, member := range checked.(map[string]interface{}) {
			object[name] = member
		}
		container[def.Name] = object
	default:
		// "If the target location specifies a single-valued attribute, the
		// existing value is replaced."
		container[def.Name] = checked
	}
	if values, isArray := container[def.Name].([]interface{}); isArray && len(values) == 0 {
		delete(container, def.Name)
	}
	return nil
}

// removeAttribute performs a remove (Section 3.5.2.2).
func removeAttribute(resource map[string]interface{}, schema *resourceSchema, path patchPath) *SCIMError {
	found, sub, scimErr := target(schema, path)
	if scimErr != nil {
		return scimErr
	}
	def := found.def
	container := found.container(resource, false)
	current, present := container[def.Name]
	unassign := func() *SCIMError {
		// 'If an attribute is removed or becomes unassigned and is defined as
		// a required attribute or a read-only attribute, the server SHALL
		// return an HTTP response status code and a JSON detail error
		// response as defined in Section 3.12, with a "scimType" error code
		// of "mutability".'
		if def.Required {
			return errRequired(def.Name)
		}
		delete(container, def.Name)
		return nil
	}

	if path.Filter == nil && sub == nil {
		// "the attribute and its associated value is removed, and the
		// attribute SHALL be considered unassigned."
		if def.Required {
			return errRequired(def.Name)
		}
		if present {
			delete(container, def.Name)
		}
		return nil
	}
	if sub != nil && sub.Required {
		return errRequired(def.Name + "." + sub.Name)
	}

	if !def.MultiValued {
		if object, isObject := current.(map[string]interface{}); isObject {
			delete(object, sub.Name)
			if len(object) == 0 {
				return unassign()
			}
		}
		return nil
	}

	values, _ := current.([]interface{})
	indexes := make([]int, len(values))
	for i := range values {
		indexes[i] = i
	}
	if path.Filter != nil {
		if indexes, scimErr = matching(def, values, path.Filter); scimErr != nil {
			return scimErr
		}
		if len(indexes) == 0 {
			// Table 9, noTarget: 'The specified "path" did not yield an
			// attribute or attribute value that could be operated on. This
			// occurs when the specified "path" value contains a filter that
			// yields no match.'
			return ErrNoTarget(fmt.Sprintf("no value of %s matches the path", def.Name))
		}
	}
	selected := map[int]bool{}
	for _, i := range indexes {
		selected[i] = true
	}
	var kept []interface{}
	for i, value := range values {
		object, _ := value.(map[string]interface{})
		switch {
		case !selected[i]:
			kept = append(kept, value)
		case sub != nil:
			// "Sub-attributes whose values have been removed SHALL be
			// considered unassigned."
			delete(object, sub.Name)
			if len(object) > 0 {
				kept = append(kept, object)
			}
		}
	}
	// "If no other values remain after removal of the selected values, the
	// multi-valued attribute SHALL be considered unassigned."
	if len(kept) == 0 {
		return unassign()
	}
	container[def.Name] = kept
	return nil
}

// errRequired refuses to leave a required attribute without a value.
func errRequired(name string) *SCIMError {
	return &SCIMError{Status: http.StatusBadRequest, ScimType: ErrorTypeMutability, Detail: fmt.Sprintf("%s is a required attribute and cannot be removed", name)}
}

// immutable refuses a change to an attribute that already has another value.
// RFC 7644 Section 3.5.2: 'a client MAY "add" a value to an "immutable"
// attribute if the attribute had no previous value.'
func immutable(def *Attribute, current, value interface{}, name string) *SCIMError {
	if def.Mutability == "immutable" && !def.MultiValued && assigned(current) && !reflect.DeepEqual(current, value) {
		return ErrMutability(name)
	}
	return nil
}

// indexOfValue finds a value of a multi-valued attribute. Two complex values
// are the same value when their "value" sub-attributes are equal.
func indexOfValue(def *Attribute, values []interface{}, value interface{}) int {
	wanted, isObject := value.(map[string]interface{})
	for i, existing := range values {
		if reflect.DeepEqual(existing, value) {
			return i
		}
		if object, ok := existing.(map[string]interface{}); ok && isObject && findAttribute(def.SubAttributes, "value") != nil &&
			assigned(wanted["value"]) && reflect.DeepEqual(object["value"], wanted["value"]) && sameOrUnset(object["type"], wanted["type"]) {
			return i
		}
	}
	return -1
}

func sameOrUnset(existing, wanted interface{}) bool {
	return wanted == nil || reflect.DeepEqual(existing, wanted)
}

// onePrimary keeps at most one primary value. 'For multi-valued attributes, a
// PATCH operation that sets a value's "primary" sub-attribute to "true" SHALL
// cause the server to automatically set "primary" to "false" for any other
// values in the array.' touched are the values the operation wrote.
func onePrimary(values []interface{}, touched []int) []interface{} {
	primary := -1
	for _, i := range touched {
		if object, ok := values[i].(map[string]interface{}); ok && object["primary"] == true {
			primary = i
		}
	}
	if primary < 0 {
		return values
	}
	for i, value := range values {
		if object, ok := value.(map[string]interface{}); ok && i != primary && object["primary"] == true {
			object["primary"] = false
		}
	}
	return values
}

// checkValue checks a value against an attribute's type (RFC 7643 Section
// 2.3) and returns it in the shape the attribute takes: an array for a
// multi-valued attribute, with read-only sub-attributes dropped from complex
// values. Table 9, invalidValue: "the value specified was not compatible with
// the operation or attribute type".
func checkValue(def *Attribute, value interface{}, name string) (interface{}, *SCIMError) {
	if def.MultiValued {
		elements, isArray := value.([]interface{})
		if !isArray {
			elements = []interface{}{value}
		}
		one := *def
		one.MultiValued = false
		out := make([]interface{}, 0, len(elements))
		for _, element := range elements {
			checked, scimErr := checkValue(&one, element, name)
			if scimErr != nil {
				return nil, scimErr
			}
			out = append(out, checked)
		}
		return out, nil
	}
	mismatch := func(want string) (interface{}, *SCIMError) {
		return nil, ErrInvalidValue(fmt.Sprintf("the value of %s must be %s", name, want))
	}
	switch def.Type {
	case "complex":
		object, ok := value.(map[string]interface{})
		if !ok {
			return mismatch("an object of sub-attributes")
		}
		out := map[string]interface{}{}
		for member, memberValue := range object {
			sub := findAttribute(def.SubAttributes, member)
			if sub == nil {
				return nil, ErrInvalidValue(fmt.Sprintf("%s has no sub-attribute %s", name, member))
			}
			if sub.Mutability == "readOnly" {
				// The service provider assigns it; what a client sends is
				// ignored, as it is on POST and PUT.
				continue
			}
			checked, scimErr := checkValue(sub, memberValue, name+"."+sub.Name)
			if scimErr != nil {
				return nil, scimErr
			}
			out[sub.Name] = checked
		}
		return out, nil
	case "boolean":
		if _, ok := value.(bool); !ok {
			return mismatch("true or false")
		}
	case "integer", "decimal":
		if _, ok := value.(float64); !ok {
			return mismatch("a number")
		}
	default:
		if _, ok := value.(string); !ok {
			return mismatch("a string")
		}
	}
	return value, nil
}
