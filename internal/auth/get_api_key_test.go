package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectErr   bool
		specificErr error
	}{
		{
			name:        "no authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectErr:   true,
			specificErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "valid ApiKey header",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectErr:   false,
		},
		{
			name:        "malformed header - missing key value",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectErr:   true,
		},
		{
			name:        "malformed header - wrong scheme",
			headers:     http.Header{"Authorization": []string{"Bearer some-token"}},
			expectedKey: "",
			expectErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if key != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, key)
			}

			if tc.expectErr && err == nil {
				t.Errorf("expected an error but got nil")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if tc.specificErr != nil && err != tc.specificErr {
				t.Errorf("expected error %v, got %v", tc.specificErr, err)
			}
		})
	}
}
