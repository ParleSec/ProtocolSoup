package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SCIMError represents a SCIM protocol error
type SCIMError struct {
	Status   int    `json:"-"`
	ScimType string `json:"scimType,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

func (e *SCIMError) Error() string {
	if e.ScimType != "" {
		return fmt.Sprintf("SCIM error %d (%s): %s", e.Status, e.ScimType, e.Detail)
	}
	return fmt.Sprintf("SCIM error %d: %s", e.Status, e.Detail)
}

// WriteError writes a SCIM error response
func WriteError(w http.ResponseWriter, err *SCIMError) {
	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.WriteHeader(err.Status)
	
	resp := ErrorResponse{
		Schemas:  []string{SchemaURNError},
		ScimType: err.ScimType,
		Detail:   err.Detail,
		Status:   fmt.Sprintf("%d", err.Status),
	}
	
	json.NewEncoder(w).Encode(resp)
}

// Common SCIM errors

// ErrBadRequest returns a 400 Bad Request error
func ErrBadRequest(detail string) *SCIMError {
	return &SCIMError{
		Status: http.StatusBadRequest,
		Detail: detail,
	}
}

// ErrInvalidFilter returns a 400 error for invalid filter syntax
func ErrInvalidFilter(detail string) *SCIMError {
	return &SCIMError{
		Status:   http.StatusBadRequest,
		ScimType: ErrorTypeInvalidFilter,
		Detail:   detail,
	}
}

// ErrInvalidSyntax returns a 400 error for invalid request syntax
func ErrInvalidSyntax(detail string) *SCIMError {
	return &SCIMError{
		Status:   http.StatusBadRequest,
		ScimType: ErrorTypeInvalidSyntax,
		Detail:   detail,
	}
}

// ErrInvalidPath returns a 400 error for invalid attribute path
func ErrInvalidPath(detail string) *SCIMError {
	return &SCIMError{
		Status:   http.StatusBadRequest,
		ScimType: ErrorTypeInvalidPath,
		Detail:   detail,
	}
}

// ErrInvalidValue returns a 400 error for invalid attribute value
func ErrInvalidValue(detail string) *SCIMError {
	return &SCIMError{
		Status:   http.StatusBadRequest,
		ScimType: ErrorTypeInvalidValue,
		Detail:   detail,
	}
}

// ErrUnauthorized returns a 401 Unauthorized error
func ErrUnauthorized(detail string) *SCIMError {
	return &SCIMError{
		Status: http.StatusUnauthorized,
		Detail: detail,
	}
}

// ErrForbidden returns a 403 Forbidden error
func ErrForbidden(detail string) *SCIMError {
	return &SCIMError{
		Status: http.StatusForbidden,
		Detail: detail,
	}
}

// ErrResourceNotFound returns a 404 Not Found error
func ErrResourceNotFound(resourceType, id string) *SCIMError {
	return &SCIMError{
		Status: http.StatusNotFound,
		Detail: fmt.Sprintf("%s %q not found", resourceType, id),
	}
}

// ErrNoTarget returns a 400 error when PATCH target doesn't exist
func ErrNoTarget(detail string) *SCIMError {
	return &SCIMError{
		Status:   http.StatusBadRequest,
		ScimType: ErrorTypeNoTarget,
		Detail:   detail,
	}
}

// ErrConflictUniqueness returns a 409 Conflict error for uniqueness violation
func ErrConflictUniqueness(attribute string) *SCIMError {
	return &SCIMError{
		Status:   http.StatusConflict,
		ScimType: ErrorTypeUniqueness,
		Detail:   fmt.Sprintf("Attribute %q must be unique", attribute),
	}
}

// ErrMutability returns a 400 error for mutability violation
func ErrMutability(attribute string) *SCIMError {
	return &SCIMError{
		Status:   http.StatusBadRequest,
		ScimType: ErrorTypeMutability,
		Detail:   fmt.Sprintf("Attribute %q is immutable or read-only", attribute),
	}
}

// ErrPreconditionFailed returns a 412 error for ETag mismatch
func ErrPreconditionFailed(detail string) *SCIMError {
	return &SCIMError{
		Status:   http.StatusPreconditionFailed,
		ScimType: ErrorTypeInvalidVers,
		Detail:   detail,
	}
}

// ErrTooMany returns a 400 error when too many results would be returned
func ErrTooMany(detail string) *SCIMError {
	return &SCIMError{
		Status:   http.StatusBadRequest,
		ScimType: ErrorTypeTooMany,
		Detail:   detail,
	}
}

// ErrInternalServer returns a 500 Internal Server Error
func ErrInternalServer(detail string) *SCIMError {
	return &SCIMError{
		Status: http.StatusInternalServerError,
		Detail: detail,
	}
}

// ErrNotImplemented returns a 501 Not Implemented error
func ErrNotImplemented(feature string) *SCIMError {
	return &SCIMError{
		Status: http.StatusNotImplemented,
		Detail: fmt.Sprintf("%s is not implemented", feature),
	}
}

// ErrPayloadTooLarge returns a 413 error for bulk operations
func ErrPayloadTooLarge(maxSize int) *SCIMError {
	return &SCIMError{
		Status: http.StatusRequestEntityTooLarge,
		Detail: fmt.Sprintf("Request payload exceeds maximum size of %d bytes", maxSize),
	}
}




