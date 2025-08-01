package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if apiKey != "my-secret-key" {
		t.Errorf("expected apiKey to be 'my-secret-key', got '%s'", apiKey)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "")
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"WrongPrefix", "Bearer token"},
		{"NoSpace", "ApiKey"},
		{"EmptyValue", "ApiKey "},
		//{"ExtraParts", "ApiKey key extra"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tt.header)
			_, err := GetAPIKey(headers)
			if err == nil || err.Error() != "malformed authorization header" {
				t.Errorf("expected malformed authorization header error, got %v", err)
			}
		})
	}
}
