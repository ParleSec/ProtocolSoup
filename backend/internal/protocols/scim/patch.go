package scim

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// PatchExecutor executes SCIM PATCH operations on resources
type PatchExecutor struct {
	resource interface{}
	changes  []PatchChange
}

// PatchChange represents a single change made during patching
type PatchChange struct {
	Path      string      `json:"path"`
	Operation string      `json:"operation"`
	OldValue  interface{} `json:"oldValue,omitempty"`
	NewValue  interface{} `json:"newValue,omitempty"`
}

// NewPatchExecutor creates a new patch executor for a resource
func NewPatchExecutor(resource interface{}) *PatchExecutor {
	return &PatchExecutor{
		resource: resource,
		changes:  make([]PatchChange, 0),
	}
}

// Execute applies PATCH operations to the resource
func (pe *PatchExecutor) Execute(operations []PatchOperation) error {
	for i, op := range operations {
		if err := pe.executeOp(op); err != nil {
			return fmt.Errorf("operation %d failed: %w", i, err)
		}
	}
	return nil
}

// GetChanges returns the list of changes made
func (pe *PatchExecutor) GetChanges() []PatchChange {
	return pe.changes
}

func (pe *PatchExecutor) executeOp(op PatchOperation) error {
	opLower := strings.ToLower(op.Op)
	
	switch opLower {
	case "add":
		return pe.executeAdd(op.Path, op.Value)
	case "remove":
		return pe.executeRemove(op.Path)
	case "replace":
		return pe.executeReplace(op.Path, op.Value)
	default:
		return fmt.Errorf("unsupported operation: %s", op.Op)
	}
}

func (pe *PatchExecutor) executeAdd(path string, value interface{}) error {
	if path == "" {
		// Add to root - value must be object with attributes to add
		return pe.addToRoot(value)
	}
	
	// Parse path and add value
	return pe.setValueAtPath(path, value, true)
}

func (pe *PatchExecutor) executeRemove(path string) error {
	if path == "" {
		return ErrNoTarget("remove operation requires a path")
	}
	
	return pe.removeValueAtPath(path)
}

func (pe *PatchExecutor) executeReplace(path string, value interface{}) error {
	if path == "" {
		// Replace root - value must be complete replacement
		return pe.replaceRoot(value)
	}
	
	return pe.setValueAtPath(path, value, false)
}

// addToRoot adds attributes from value to the root resource
func (pe *PatchExecutor) addToRoot(value interface{}) error {
	valueMap, ok := value.(map[string]interface{})
	if !ok {
		return ErrInvalidValue("add to root requires an object value")
	}
	
	// Convert resource to map, merge, convert back
	resourceMap, err := pe.resourceToMap()
	if err != nil {
		return err
	}
	
	for k, v := range valueMap {
		pe.changes = append(pe.changes, PatchChange{
			Path:      k,
			Operation: "add",
			OldValue:  resourceMap[k],
			NewValue:  v,
		})
		resourceMap[k] = v
	}
	
	return pe.mapToResource(resourceMap)
}

// replaceRoot replaces the entire resource
func (pe *PatchExecutor) replaceRoot(value interface{}) error {
	valueMap, ok := value.(map[string]interface{})
	if !ok {
		return ErrInvalidValue("replace root requires an object value")
	}
	
	oldMap, _ := pe.resourceToMap()
	
	// Preserve immutable attributes
	if id, ok := oldMap["id"]; ok {
		valueMap["id"] = id
	}
	if meta, ok := oldMap["meta"]; ok {
		valueMap["meta"] = meta
	}
	if schemas, ok := oldMap["schemas"]; ok {
		valueMap["schemas"] = schemas
	}
	
	pe.changes = append(pe.changes, PatchChange{
		Path:      "",
		Operation: "replace",
		OldValue:  oldMap,
		NewValue:  valueMap,
	})
	
	return pe.mapToResource(valueMap)
}

// setValueAtPath sets a value at a JSON path
func (pe *PatchExecutor) setValueAtPath(path string, value interface{}, isAdd bool) error {
	resourceMap, err := pe.resourceToMap()
	if err != nil {
		return err
	}
	
	// Parse path components
	components, valueFilter, err := parsePatchPath(path)
	if err != nil {
		return err
	}
	
	// Navigate to parent and set value
	current := resourceMap
	for i := 0; i < len(components)-1; i++ {
		comp := components[i]
		
		if next, ok := current[comp]; ok {
			switch v := next.(type) {
			case map[string]interface{}:
				current = v
			case []interface{}:
				// Handle array navigation with filter
				if valueFilter != "" && i == len(components)-2 {
					return pe.setInArray(v, valueFilter, components[len(components)-1], value, isAdd, path)
				}
				return ErrInvalidPath(fmt.Sprintf("cannot navigate through array without filter at %s", comp))
			default:
				if isAdd {
					// Create intermediate object
					newMap := make(map[string]interface{})
					current[comp] = newMap
					current = newMap
				} else {
					return ErrNoTarget(fmt.Sprintf("path element %s does not exist", comp))
				}
			}
		} else if isAdd {
			// Create intermediate object
			newMap := make(map[string]interface{})
			current[comp] = newMap
			current = newMap
		} else {
			return ErrNoTarget(fmt.Sprintf("path element %s does not exist", comp))
		}
	}
	
	// Set the final value
	finalKey := components[len(components)-1]
	oldValue := current[finalKey]
	
	if isAdd && oldValue != nil {
		// For add, merge arrays or object properties
		if oldArr, ok := oldValue.([]interface{}); ok {
			if newArr, ok := value.([]interface{}); ok {
				current[finalKey] = append(oldArr, newArr...)
			} else {
				current[finalKey] = append(oldArr, value)
			}
		} else {
			current[finalKey] = value
		}
	} else {
		current[finalKey] = value
	}
	
	operation := "add"
	if !isAdd {
		operation = "replace"
	}
	pe.changes = append(pe.changes, PatchChange{
		Path:      path,
		Operation: operation,
		OldValue:  oldValue,
		NewValue:  value,
	})
	
	return pe.mapToResource(resourceMap)
}

// setInArray sets a value in an array matching a filter
func (pe *PatchExecutor) setInArray(arr []interface{}, filter, subAttr string, value interface{}, isAdd bool, fullPath string) error {
	// Parse the value filter (e.g., type eq "work")
	filterExpr, err := ParseFilter(filter)
	if err != nil {
		return ErrInvalidPath(fmt.Sprintf("invalid value filter: %s", filter))
	}
	
	// Find matching element(s)
	matched := false
	for i, elem := range arr {
		elemMap, ok := elem.(map[string]interface{})
		if !ok {
			continue
		}
		
		if matchesFilter(elemMap, filterExpr) {
			matched = true
			oldValue := elemMap[subAttr]
			elemMap[subAttr] = value
			arr[i] = elemMap
			
			operation := "add"
			if !isAdd {
				operation = "replace"
			}
			pe.changes = append(pe.changes, PatchChange{
				Path:      fullPath,
				Operation: operation,
				OldValue:  oldValue,
				NewValue:  value,
			})
		}
	}
	
	if !matched && !isAdd {
		return ErrNoTarget(fmt.Sprintf("no array element matches filter: %s", filter))
	}
	
	return nil
}

// removeValueAtPath removes a value at a JSON path
func (pe *PatchExecutor) removeValueAtPath(path string) error {
	resourceMap, err := pe.resourceToMap()
	if err != nil {
		return err
	}
	
	components, valueFilter, err := parsePatchPath(path)
	if err != nil {
		return err
	}
	
	// Navigate to parent
	current := resourceMap
	for i := 0; i < len(components)-1; i++ {
		comp := components[i]
		
		if next, ok := current[comp]; ok {
			switch v := next.(type) {
			case map[string]interface{}:
				current = v
			case []interface{}:
				if valueFilter != "" {
					return pe.removeFromArray(current, comp, v, valueFilter, path)
				}
				return ErrInvalidPath(fmt.Sprintf("cannot navigate through array without filter at %s", comp))
			default:
				return ErrNoTarget(fmt.Sprintf("path element %s is not an object", comp))
			}
		} else {
			return ErrNoTarget(fmt.Sprintf("path element %s does not exist", comp))
		}
	}
	
	// Remove the final key
	finalKey := components[len(components)-1]
	
	if valueFilter != "" {
		// Remove from array with filter
		if arr, ok := current[finalKey].([]interface{}); ok {
			return pe.removeFromArray(current, finalKey, arr, valueFilter, path)
		}
	}
	
	oldValue := current[finalKey]
	if oldValue == nil {
		return ErrNoTarget(fmt.Sprintf("attribute %s does not exist", finalKey))
	}
	
	delete(current, finalKey)
	
	pe.changes = append(pe.changes, PatchChange{
		Path:      path,
		Operation: "remove",
		OldValue:  oldValue,
	})
	
	return pe.mapToResource(resourceMap)
}

// removeFromArray removes elements from an array matching a filter
func (pe *PatchExecutor) removeFromArray(parent map[string]interface{}, key string, arr []interface{}, filter, fullPath string) error {
	filterExpr, err := ParseFilter(filter)
	if err != nil {
		return ErrInvalidPath(fmt.Sprintf("invalid value filter: %s", filter))
	}
	
	newArr := make([]interface{}, 0, len(arr))
	removed := make([]interface{}, 0)
	
	for _, elem := range arr {
		elemMap, ok := elem.(map[string]interface{})
		if !ok {
			newArr = append(newArr, elem)
			continue
		}
		
		if matchesFilter(elemMap, filterExpr) {
			removed = append(removed, elem)
		} else {
			newArr = append(newArr, elem)
		}
	}
	
	if len(removed) == 0 {
		return ErrNoTarget(fmt.Sprintf("no array element matches filter: %s", filter))
	}
	
	parent[key] = newArr
	
	pe.changes = append(pe.changes, PatchChange{
		Path:      fullPath,
		Operation: "remove",
		OldValue:  removed,
	})
	
	return nil
}

// parsePatchPath parses a SCIM PATCH path into components
// Returns (path components, value filter if any, error)
func parsePatchPath(path string) ([]string, string, error) {
	if path == "" {
		return nil, "", nil
	}
	
	// Check for value filter: attr[filter].subAttr
	var valueFilter string
	if idx := strings.Index(path, "["); idx != -1 {
		endIdx := strings.Index(path, "]")
		if endIdx == -1 {
			return nil, "", ErrInvalidPath("unclosed bracket in path")
		}
		valueFilter = path[idx+1 : endIdx]
		path = path[:idx] + path[endIdx+1:]
	}
	
	// Split by dots
	components := strings.Split(path, ".")
	
	// Filter empty components
	filtered := make([]string, 0, len(components))
	for _, c := range components {
		if c != "" {
			filtered = append(filtered, c)
		}
	}
	
	if len(filtered) == 0 {
		return nil, "", ErrInvalidPath("empty path")
	}
	
	return filtered, valueFilter, nil
}

// matchesFilter checks if a map matches a filter expression
func matchesFilter(obj map[string]interface{}, filter *Filter) bool {
	if filter == nil || filter.Root == nil {
		return true
	}
	return evaluateFilterNode(obj, filter.Root)
}

func evaluateFilterNode(obj map[string]interface{}, node FilterNode) bool {
	switch n := node.(type) {
	case *AttrExpr:
		return evaluateAttrExpr(obj, n)
	case *LogExpr:
		left := evaluateFilterNode(obj, n.Left)
		right := evaluateFilterNode(obj, n.Right)
		if n.Operator == "and" {
			return left && right
		}
		return left || right
	case *NotExpr:
		return !evaluateFilterNode(obj, n.Expr)
	}
	return false
}

func evaluateAttrExpr(obj map[string]interface{}, expr *AttrExpr) bool {
	// Get value at path
	val := getValueAtPath(obj, expr.Path)
	
	// Handle presence check
	if expr.Operator == "pr" {
		return val != nil
	}
	
	// Compare values
	return compareValues(val, expr.Operator, expr.Value)
}

func getValueAtPath(obj map[string]interface{}, path *AttrPath) interface{} {
	val, ok := obj[path.Attribute]
	if !ok {
		// Try lowercase
		val, ok = obj[strings.ToLower(path.Attribute)]
		if !ok {
			return nil
		}
	}
	
	if path.SubAttr != "" {
		if subObj, ok := val.(map[string]interface{}); ok {
			val = subObj[path.SubAttr]
			if val == nil {
				val = subObj[strings.ToLower(path.SubAttr)]
			}
		} else {
			return nil
		}
	}
	
	return val
}

func compareValues(actual interface{}, op string, expected interface{}) bool {
	// Convert to strings for comparison
	actualStr := fmt.Sprintf("%v", actual)
	expectedStr := fmt.Sprintf("%v", expected)
	
	switch op {
	case "eq":
		return strings.EqualFold(actualStr, expectedStr)
	case "ne":
		return !strings.EqualFold(actualStr, expectedStr)
	case "co":
		return strings.Contains(strings.ToLower(actualStr), strings.ToLower(expectedStr))
	case "sw":
		return strings.HasPrefix(strings.ToLower(actualStr), strings.ToLower(expectedStr))
	case "ew":
		return strings.HasSuffix(strings.ToLower(actualStr), strings.ToLower(expectedStr))
	case "gt", "lt", "ge", "le":
		return compareNumeric(actual, op, expected)
	}
	return false
}

func compareNumeric(actual interface{}, op string, expected interface{}) bool {
	actualNum, err1 := toFloat64(actual)
	expectedNum, err2 := toFloat64(expected)
	
	if err1 != nil || err2 != nil {
		// Fall back to string comparison
		actualStr := fmt.Sprintf("%v", actual)
		expectedStr := fmt.Sprintf("%v", expected)
		switch op {
		case "gt":
			return actualStr > expectedStr
		case "lt":
			return actualStr < expectedStr
		case "ge":
			return actualStr >= expectedStr
		case "le":
			return actualStr <= expectedStr
		}
		return false
	}
	
	switch op {
	case "gt":
		return actualNum > expectedNum
	case "lt":
		return actualNum < expectedNum
	case "ge":
		return actualNum >= expectedNum
	case "le":
		return actualNum <= expectedNum
	}
	return false
}

func toFloat64(v interface{}) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case string:
		return strconv.ParseFloat(n, 64)
	}
	return 0, fmt.Errorf("cannot convert to float64")
}

// resourceToMap converts the resource to a map[string]interface{}
func (pe *PatchExecutor) resourceToMap() (map[string]interface{}, error) {
	data, err := json.Marshal(pe.resource)
	if err != nil {
		return nil, err
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	
	return result, nil
}

// mapToResource converts a map back to the resource
func (pe *PatchExecutor) mapToResource(m map[string]interface{}) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	
	// Get the underlying value
	val := reflect.ValueOf(pe.resource)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	
	// Create a new instance and unmarshal
	newVal := reflect.New(val.Type())
	if err := json.Unmarshal(data, newVal.Interface()); err != nil {
		return err
	}
	
	// Copy the new value to the original
	val.Set(newVal.Elem())
	
	return nil
}

// ApplyPatch applies PATCH operations to a User
func ApplyPatchToUser(user *User, request *PatchRequest) ([]PatchChange, error) {
	if len(request.Schemas) > 0 && request.Schemas[0] != SchemaURNPatchOp {
		return nil, ErrInvalidSyntax(fmt.Sprintf("expected schema %s", SchemaURNPatchOp))
	}
	
	executor := NewPatchExecutor(user)
	if err := executor.Execute(request.Operations); err != nil {
		return nil, err
	}
	
	return executor.GetChanges(), nil
}

// ApplyPatchToGroup applies PATCH operations to a Group
func ApplyPatchToGroup(group *Group, request *PatchRequest) ([]PatchChange, error) {
	if len(request.Schemas) > 0 && request.Schemas[0] != SchemaURNPatchOp {
		return nil, ErrInvalidSyntax(fmt.Sprintf("expected schema %s", SchemaURNPatchOp))
	}
	
	executor := NewPatchExecutor(group)
	if err := executor.Execute(request.Operations); err != nil {
		return nil, err
	}
	
	return executor.GetChanges(), nil
}

