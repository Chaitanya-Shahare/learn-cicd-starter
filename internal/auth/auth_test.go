package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("returns error when no Authorization header", func(t *testing.T) {
		headers := http.Header{}

		_, err := GetAPIKey(headers)

		if err == nil {
			t.Errorf("expected an error, got none")
		}

		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("returns error when Authorization header is malformed", func(t *testing.T) {
		headers := http.Header{}
		headers.Add("Authorization", "malformed")

		_, err := GetAPIKey(headers)

		if err == nil {
			t.Errorf("expected an error, got none")
		}

		if err.Error() != "malformed authorization header" {
			t.Errorf("expected 'malformed authorization header', got %v", err)
		}
	})

	t.Run("returns API key when Authorization header is well formed", func(t *testing.T) {
		headers := http.Header{}
		headers.Add("Authorization", "ApiKey myapikey")

		apiKey, err := GetAPIKey(headers)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		if apiKey != "myapikey" {
			t.Errorf("expected 'myapikey', got %v", apiKey)
		}
	})
}
