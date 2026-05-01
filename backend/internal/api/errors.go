package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

const (
	ErrCodeInvalidID         = "invalid_id"
	ErrCodeContainerMissing  = "container_not_found"
	ErrCodeAmbiguousPrefix   = "ambiguous_container_prefix"
	ErrCodeDockerUnavailable = "docker_unavailable"
	ErrCodeApplyFailed       = "apply_failed"
	ErrCodeDisableFailed     = "disable_failed"
	ErrCodeInternal          = "internal_error"
	ErrCodeInvalidBody       = "invalid_body"
)

func respondError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, APIError{Code: code, Message: message})
}

func respondErrorDetails(c *gin.Context, status int, code, message, details string) {
	c.AbortWithStatusJSON(status, APIError{Code: code, Message: message, Details: details})
}

func respondInternalError(c *gin.Context, code, userMessage string, err error) {
	if logger, ok := c.Get("logger"); ok {
		if l, ok := logger.(interface{ Error(msg string, args ...any) }); ok {
			l.Error(userMessage, "error", err)
		}
	}
	c.AbortWithStatusJSON(http.StatusInternalServerError, APIError{Code: code, Message: userMessage})
}
