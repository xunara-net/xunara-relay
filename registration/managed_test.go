package registration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedEnrollmentCarriesMapCertificateWithoutURLSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.RawQuery != "" || request.Header.Get("Authorization") != "Bearer enrollment-secret" {
			t.Error("credential transport changed")
		}
		var enrollment EnrollRequest
		if err := json.NewDecoder(request.Body).Decode(&enrollment); err != nil {
			t.Fatal(err)
		}
		if enrollment.RegionID != 40001 || enrollment.CertName != "sha256-raw:"+strings.Repeat("a", 64) {
			t.Error("map metadata was not sent")
		}
		json.NewEncoder(writer).Encode(Identity{RelayID: "relay-test", Token: "long-lived-secret", ControlURL: "https://tenant.example.test"})
	}))
	defer server.Close()
	client := &Client{ControlURL: server.URL + "/", Token: "enrollment-secret"}
	if _, err := client.Enroll(t.Context(), EnrollRequest{RegionID: 40001, CertName: "sha256-raw:" + strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
}

func TestRelayCredentialsAreNotReplayedThroughRedirects(t *testing.T) {
	var replayed bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == EnrollPath {
			http.Redirect(writer, request, "/redirected", http.StatusTemporaryRedirect)
			return
		}
		replayed = true
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := &Client{ControlURL: server.URL, Token: "secret"}
	if _, err := client.Enroll(context.Background(), EnrollRequest{}); err == nil {
		t.Fatal("redirect was reported as enrollment success")
	}
	if replayed {
		t.Fatal("service credential was replayed to a redirect target")
	}
}

func TestIncompleteStoredIdentityDoesNotDowngradeToStandalone(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(filename, []byte(`{"relay_id":"existing","control_url":"https://tenant.example.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := LoadIdentity(filename); err == nil || found {
		t.Fatal("incomplete identity was silently treated as an unenrolled relay")
	}
}
