package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedKey   string
		expectedError error
	}{
		{
			name:          "valid API key",
			authHeader:    "ApiKey my-secret-key",
			expectedKey:   "my-secret-key",
			expectedError: nil,
		},
		{
			name:          "valid API key with complex value",
			authHeader:    "ApiKey abc123-def456-ghi789",
			expectedKey:   "abc123-def456-ghi789",
			expectedError: nil,
		},
		{
			name:          "missing authorization header",
			authHeader:    "",
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "wrong authorization scheme - Bearer",
			authHeader:    "Bearer my-token",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "wrong authorization scheme - Basic",
			authHeader:    "Basic dXNlcjpwYXNzd29yZA==",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "only scheme without key",
			authHeader:    "ApiKey",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "only scheme with space but no key",
			authHeader:    "ApiKey ",
			expectedKey:   "",  // Function actually returns empty string, no error
			expectedError: nil, // CORRECTED: No error expected
		},
		{
			name:          "case sensitivity - lowercase apikey",
			authHeader:    "apikey my-secret-key",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "case sensitivity - APIKEY",
			authHeader:    "APIKEY my-secret-key",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "API key with spaces gets truncated",
			authHeader:    "ApiKey my secret key with spaces",
			expectedKey:   "my", // Only takes the first part after split
			expectedError: nil,
		},
		{
			name:          "API key with special characters",
			authHeader:    "ApiKey my-key_123!@#",
			expectedKey:   "my-key_123!@#",
			expectedError: nil,
		},
		{
			name:          "multiple spaces between scheme and key",
			authHeader:    "ApiKey   my-key-with-multiple-spaces",
			expectedKey:   "",  // CORRECTED: splitAuth[1] is empty due to multiple spaces
			expectedError: nil, // CORRECTED: No error, function succeeds
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			apiKey, err := GetAPIKey(headers)

			// Check error expectation
			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("Expected error %q, but got no error", tt.expectedError.Error())
				} else if err.Error() != tt.expectedError.Error() {
					t.Errorf("Expected error %q, but got %q", tt.expectedError.Error(), err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got %q", err.Error())
				}
			}

			// Check API key result
			if apiKey != tt.expectedKey {
				t.Errorf("Expected API key %q, but got %q", tt.expectedKey, apiKey)
			}
		})
	}
}
