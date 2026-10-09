package main

import "testing"

func TestManagedRelayAdmissionUsesDurableTenantURL(t *testing.T) {
	for _, sample := range []struct{ control, explicit, expected string }{
		{"https://tenant.example.test", "", "https://tenant.example.test/derp/admit"},
		{"http://127.0.0.1:9190/", "", "http://127.0.0.1:9190/derp/admit"},
		{"https://tenant.example.test", "http://127.0.0.1:9190/derp/admit", "http://127.0.0.1:9190/derp/admit"},
		{"", "", ""},
	} {
		actual, err := managedAdmissionURL(sample.control, sample.explicit)
		if err != nil || actual != sample.expected {
			t.Fatalf("admission selection: %q %v", actual, err)
		}
	}
	for _, address := range []string{"https://user:secret@example.test", "https://example.test?token=secret", "file:///tmp/identity", "https://example.test/path", "https://example.test/#secret"} {
		if _, err := managedAdmissionURL(address, ""); err == nil {
			t.Fatal("unsafe control address accepted")
		}
	}
}
