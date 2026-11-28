package scim

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Queries (RFC 7644 Section 3.4.2): filtering, sorting, pagination and the
// choice of attributes to return. A query runs in memory over every resource
// of the types it covers; the store holds the demo data and what visitors
// created within the retention period.

// maxResults is the most resources one page carries. ServiceProviderConfig
// publishes it as filter.maxResults.
const maxResults = 200

// query is one parsed query, from URL parameters or a SearchRequest.
type query struct {
	filter     filterNode
	sortBy     *attrPath
	descending bool
	startIndex int
	// count is the page size the client asked for, or -1 when it gave none.
	count      int
	projection projection
}

// projection is the client's choice of attributes to return (RFC 7644
// Section 3.9).
type projection struct {
	attributes []attrPath
	excluded   []attrPath
}

func (p projection) empty() bool { return len(p.attributes) == 0 && len(p.excluded) == 0 }

// queryItem is one resource in a query: the representation to return, and the
// same decoded for filtering and sorting.
type queryItem struct {
	raw    json.RawMessage
	object map[string]interface{}
}

func newQueryItem(resource interface{}) (queryItem, error) {
	raw, err := json.Marshal(resource)
	if err != nil {
		return queryItem{}, err
	}
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		return queryItem{}, err
	}
	return queryItem{raw: raw, object: object}, nil
}

// parseAttributeList parses a list of attribute names "in standard attribute
// notation (Section 3.10) form".
func parseAttributeList(names []string) ([]attrPath, *SCIMError) {
	var paths []attrPath
	for _, list := range names {
		for _, name := range strings.Split(list, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			path, err := parseAttrPath(name)
			if err != nil {
				return nil, ErrInvalidValue(err.Error())
			}
			paths = append(paths, path)
		}
	}
	return paths, nil
}

// newProjection builds a projection. RFC 7644 Section 3.9 names "either of
// the mutually exclusive URL query parameters "attributes" or
// "excludedAttributes"".
func newProjection(attributes, excluded []string) (projection, *SCIMError) {
	var p projection
	var scimErr *SCIMError
	if p.attributes, scimErr = parseAttributeList(attributes); scimErr != nil {
		return p, scimErr
	}
	if p.excluded, scimErr = parseAttributeList(excluded); scimErr != nil {
		return p, scimErr
	}
	if len(p.attributes) > 0 && len(p.excluded) > 0 {
		return p, ErrInvalidValue("attributes and excludedAttributes are mutually exclusive (RFC 7644 Section 3.9)")
	}
	return p, nil
}

// projectionOf reads the projection of a request URL.
func projectionOf(values url.Values) (projection, *SCIMError) {
	return newProjection(values["attributes"], values["excludedAttributes"])
}

// newQuery assembles a query from its parts, as strings. hasFilter tells an
// absent filter from an empty one.
func newQuery(filter string, hasFilter bool, sortBy, sortOrder string, startIndex, count *int, p projection) (query, *SCIMError) {
	q := query{startIndex: 1, count: -1, projection: p}
	if hasFilter {
		node, err := ParseFilter(filter)
		if err != nil {
			return q, ErrInvalidFilter(err.Error())
		}
		q.filter = node
	}
	if sortBy != "" {
		path, err := parseAttrPath(sortBy)
		if err != nil {
			return q, ErrInvalidValue("sortBy: " + err.Error())
		}
		q.sortBy = &path
	}
	// sortOrder: 'Allowed values are "ascending" and "descending".'
	switch sortOrder {
	case "", "ascending":
	case "descending":
		q.descending = true
	default:
		return q, ErrInvalidValue(fmt.Sprintf("sortOrder %q is neither ascending nor descending", sortOrder))
	}
	// Table 6: for startIndex, "A value less than 1 SHALL be interpreted as
	// 1." For count, "A negative value SHALL be interpreted as "0"."
	if startIndex != nil && *startIndex > 1 {
		q.startIndex = *startIndex
	}
	if count != nil {
		q.count = *count
		if q.count < 0 {
			q.count = 0
		}
	}
	return q, nil
}

// queryFromURL reads a query from URL parameters. RFC 7644 Section 3.4.2:
// service providers "SHOULD ignore any query parameters they do not
// recognize".
func queryFromURL(values url.Values) (query, *SCIMError) {
	p, scimErr := projectionOf(values)
	if scimErr != nil {
		return query{}, scimErr
	}
	integer := func(name string) (*int, *SCIMError) {
		if !values.Has(name) {
			return nil, nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(values.Get(name)))
		if err != nil {
			return nil, ErrInvalidValue(fmt.Sprintf("%s %q is not an integer", name, values.Get(name)))
		}
		return &n, nil
	}
	startIndex, scimErr := integer("startIndex")
	if scimErr != nil {
		return query{}, scimErr
	}
	count, scimErr := integer("count")
	if scimErr != nil {
		return query{}, scimErr
	}
	return newQuery(values.Get("filter"), values.Has("filter"), values.Get("sortBy"), values.Get("sortOrder"), startIndex, count, p)
}

// queryFromSearchRequest reads a query from the body of a POST to a
// "/.search" endpoint (RFC 7644 Section 3.4.3).
func queryFromSearchRequest(body []byte) (query, *SCIMError) {
	var request struct {
		Schemas            []string `json:"schemas"`
		Attributes         []string `json:"attributes"`
		ExcludedAttributes []string `json:"excludedAttributes"`
		Filter             *string  `json:"filter"`
		SortBy             string   `json:"sortBy"`
		SortOrder          string   `json:"sortOrder"`
		StartIndex         *int     `json:"startIndex"`
		Count              *int     `json:"count"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return query{}, ErrInvalidSyntax("Invalid JSON: " + err.Error())
	}
	// "Query requests MUST be identified using the following URI:
	// "urn:ietf:params:scim:api:messages:2.0:SearchRequest"."
	if scimErr := checkSchemas(request.Schemas, SchemaURNSearchRequest); scimErr != nil {
		return query{}, scimErr
	}
	p, scimErr := newProjection(request.Attributes, request.ExcludedAttributes)
	if scimErr != nil {
		return query{}, scimErr
	}
	filter := ""
	if request.Filter != nil {
		filter = *request.Filter
	}
	return newQuery(filter, request.Filter != nil, request.SortBy, request.SortOrder, request.StartIndex, request.Count, p)
}

// run applies the query to items and builds the list response.
func (q query) run(items []queryItem) (*ListResponse, *SCIMError) {
	matched := items
	if q.filter != nil {
		matched = nil
		for _, item := range items {
			// With more than one resource type in the query, an attribute a
			// type does not define has no value there (Section 3.4.2.1).
			ok, err := matchResource(q.filter, item.object, schemaOf(item.object))
			if err != nil {
				return nil, ErrInvalidFilter(err.Error())
			}
			if ok {
				matched = append(matched, item)
			}
		}
	}
	if q.sortBy != nil {
		q.sort(matched)
	}

	total := len(matched)
	// Table 6, count: "If unspecified, the maximum number of results is set
	// by the service provider", and when specified the service provider "MAY
	// return fewer results".
	size := q.count
	if size < 0 || size > maxResults {
		size = maxResults
	}
	first := q.startIndex - 1
	if first > total {
		first = total
	}
	last := first + size
	if last > total {
		last = total
	}
	response := &ListResponse{
		Schemas:      []string{SchemaURNListResponse},
		TotalResults: total,
		StartIndex:   q.startIndex,
		ItemsPerPage: last - first,
		Resources:    []json.RawMessage{},
	}
	for _, item := range matched[first:last] {
		raw := item.raw
		if !q.projection.empty() {
			projected, err := json.Marshal(q.projection.apply(item.object))
			if err != nil {
				return nil, ErrInternalServer(err.Error())
			}
			raw = projected
		}
		response.Resources = append(response.Resources, raw)
	}
	return response, nil
}

// ================== Sorting (RFC 7644 Section 3.4.2.3) ==================

// sortValue is the value a resource is ordered by. sortBy: "if it's a
// multi-valued attribute, resources are sorted by the value of the primary
// attribute (see Section 2.4 of [RFC7643]), if any, or else the first value
// in the list, if any."
func sortValue(object map[string]interface{}, path attrPath) (*Attribute, interface{}) {
	found, ok := schemaOf(object).locate(path)
	if !ok {
		return nil, nil
	}
	raw := found.container(object, false)[found.def.Name]
	if found.def.MultiValued {
		elements, _ := raw.([]interface{})
		raw = nil
		for _, element := range elements {
			if raw == nil {
				raw = element
			}
			if value, isObject := element.(map[string]interface{}); isObject && value["primary"] == true {
				raw = element
				break
			}
		}
	}
	// "If the attribute is complex, the attribute name must be a path to a
	// sub-attribute in standard attribute notation". A multi-valued complex
	// attribute named alone is sorted by its "value" sub-attribute.
	one := *found.def
	one.MultiValued = false
	sub := path.Sub
	if found.def.Type == "complex" && sub == "" && !found.def.MultiValued {
		return nil, nil
	}
	leaf, values := subLeaves(&one, raw, sub)
	if leaf == nil || len(values) == 0 {
		return leaf, nil
	}
	return leaf, values[0]
}

// sort orders items by sortBy. "For all attribute types, if there is no data
// for the specified "sortBy" value, they are sorted via the "sortOrder"
// parameter, i.e., they are ordered last if ascending and first if
// descending."
func (q query) sort(items []queryItem) {
	keyed := make([]struct {
		item  queryItem
		def   *Attribute
		value interface{}
	}, len(items))
	for i := range items {
		keyed[i].item = items[i]
		keyed[i].def, keyed[i].value = sortValue(items[i].object, *q.sortBy)
	}
	sort.SliceStable(keyed, func(i, j int) bool {
		a, b := keyed[i], keyed[j]
		if a.value == nil || b.value == nil {
			// No data sorts after data when ascending, before it when
			// descending.
			if q.descending {
				return a.value == nil && b.value != nil
			}
			return a.value != nil && b.value == nil
		}
		order := compareSortValues(a.def, a.value, b.value)
		if q.descending {
			return order > 0
		}
		return order < 0
	})
	for i := range keyed {
		items[i] = keyed[i].item
	}
}

// compareSortValues orders two values of one attribute. '"sortOrder" MUST
// sort according to the attribute type; i.e., for case-insensitive
// attributes, sort the result using case-insensitive Unicode alphabetic sort
// order with no specific locale implied, and for case-exact attribute types,
// sort the result using case-sensitive Unicode alphabetic sort order.'
func compareSortValues(def *Attribute, a, b interface{}) int {
	switch def.Type {
	case "boolean":
		x, _ := a.(bool)
		y, _ := b.(bool)
		switch {
		case x == y:
			return 0
		case !x:
			return -1
		}
		return 1
	case "integer", "decimal":
		x, _ := a.(float64)
		y, _ := b.(float64)
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	case "dateTime":
		x, xErr := time.Parse(time.RFC3339Nano, fmt.Sprint(a))
		y, yErr := time.Parse(time.RFC3339Nano, fmt.Sprint(b))
		if xErr == nil && yErr == nil {
			return x.Compare(y)
		}
	}
	x, y := fmt.Sprint(a), fmt.Sprint(b)
	if def.Type == "string" && !def.CaseExact {
		x, y = strings.ToLower(x), strings.ToLower(y)
	}
	return strings.Compare(x, y)
}

// ================== Attributes to return (RFC 7644 Section 3.9) ==================

// apply returns the representation a projection leaves of a resource.
//
// attributes: "each resource returned MUST contain the minimum set of
// resource attributes and any attributes or sub-attributes explicitly
// requested". excludedAttributes: "each resource returned MUST contain the
// minimum set of resource attributes. Additionally, the default set of
// attributes minus those attributes listed in "excludedAttributes" is
// returned." The minimum set is the attributes whose "returned" is "always".
func (p projection) apply(resource map[string]interface{}) map[string]interface{} {
	schema := schemaOf(resource)
	if len(p.excluded) > 0 {
		out := deepCopy(resource).(map[string]interface{})
		for _, path := range p.excluded {
			found, ok := schema.locate(path)
			// excludedAttributes "SHALL have no effect on attributes whose
			// schema "returned" setting is "always"".
			if !ok || found.def.Returned == "always" {
				continue
			}
			container := found.container(out, false)
			if container == nil {
				continue
			}
			if path.Sub == "" {
				delete(container, found.def.Name)
				continue
			}
			sub := findAttribute(found.def.SubAttributes, path.Sub)
			if sub == nil || sub.Returned == "always" {
				continue
			}
			forEachValue(container[found.def.Name], func(value map[string]interface{}) { delete(value, sub.Name) })
		}
		dropEmptyExtensions(out, schema)
		return out
	}

	out := map[string]interface{}{}
	for i := range commonAttributes {
		if def := &commonAttributes[i]; def.Returned == "always" {
			if value, present := resource[def.Name]; present {
				out[def.Name] = value
			}
		}
	}
	for _, path := range p.attributes {
		found, ok := schema.locate(path)
		if !ok || found.def.Returned == "never" {
			continue
		}
		source := found.container(resource, false)
		value, present := source[found.def.Name]
		if !present {
			continue
		}
		target := found.container(out, true)
		if path.Sub == "" {
			target[found.def.Name] = value
			continue
		}
		sub := findAttribute(found.def.SubAttributes, path.Sub)
		if sub == nil || sub.Returned == "never" {
			continue
		}
		target[found.def.Name] = mergeSubAttribute(target[found.def.Name], value, sub.Name)
	}
	dropEmptyExtensions(out, schema)
	return out
}

// mergeSubAttribute adds one sub-attribute of source to what a projection
// has already selected of the same attribute.
func mergeSubAttribute(selected, source interface{}, sub string) interface{} {
	pick := func(into interface{}, from interface{}) interface{} {
		object, _ := from.(map[string]interface{})
		out, _ := into.(map[string]interface{})
		if out == nil {
			out = map[string]interface{}{}
		}
		if value, present := object[sub]; present {
			out[sub] = value
		}
		return out
	}
	elements, isArray := source.([]interface{})
	if !isArray {
		return pick(selected, source)
	}
	chosen, _ := selected.([]interface{})
	out := make([]interface{}, len(elements))
	for i, element := range elements {
		var into interface{}
		if i < len(chosen) {
			into = chosen[i]
		}
		out[i] = pick(into, element)
	}
	return out
}

// forEachValue calls fn on each value of a complex attribute.
func forEachValue(raw interface{}, fn func(map[string]interface{})) {
	switch typed := raw.(type) {
	case map[string]interface{}:
		fn(typed)
	case []interface{}:
		for _, element := range typed {
			if object, ok := element.(map[string]interface{}); ok {
				fn(object)
			}
		}
	}
}

// dropEmptyExtensions removes an extension object a projection left empty.
func dropEmptyExtensions(resource map[string]interface{}, schema *resourceSchema) {
	for _, extension := range schema.extensions {
		if object, ok := resource[extension.ID].(map[string]interface{}); ok && len(object) == 0 {
			delete(resource, extension.ID)
		}
	}
}

// deepCopy copies a decoded JSON value.
func deepCopy(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for key, member := range typed {
			out[key] = deepCopy(member)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, element := range typed {
			out[i] = deepCopy(element)
		}
		return out
	default:
		return value
	}
}
