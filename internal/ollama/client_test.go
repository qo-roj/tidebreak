package ollama

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSummarizeTwoStageRedaction(t *testing.T) {
	// Mock Ollama that returns a summary with PII still in it
	// (simulates a local model that missed some PII)
	ollamaResp := SummarizeResponse{
		Response: "Config for admin@myapp.com with IP 203.0.113.42 and token ghp_1234567890abcdefghijklmnopqrstuvwxyz1234",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req SummarizeRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Model != "llama3:8b" {
			t.Errorf("expected model llama3:8b, got %s", req.Model)
		}
		if req.Stream != false {
			t.Error("expected stream=false")
		}

		json.NewEncoder(w).Encode(ollamaResp)
	}))
	defer server.Close()

	client := New(server.URL, "llama3:8b")
	defer client.Close()

	result, err := client.Summarize("raw content with secrets")
	if err != nil {
		t.Fatal(err)
	}

	// Stage 1 (Ollama) left PII in — stage 2 (regex) should have caught it
	// Check that the output no longer contains the raw PII
	if containsStr(result, "admin@myapp.com") {
		t.Error("stage 2 should have redacted email from Ollama summary")
	}
	if containsStr(result, "203.0.113.42") {
		t.Error("stage 2 should have redacted IP from Ollama summary")
	}
	if containsStr(result, "ghp_") {
		t.Error("stage 2 should have redacted GitHub token from Ollama summary")
	}
}

func TestSummarizeOllamaError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("model not found"))
	}))
	defer server.Close()

	client := New(server.URL, "llama3:8b")
	defer client.Close()

	_, err := client.Summarize("content")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestSummarizeOllamaConnectionRefused(t *testing.T) {
	client := New("http://localhost:99999", "llama3:8b")
	defer client.Close()

	_, err := client.Summarize("content")
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestAvailableTrue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := New(server.URL, "llama3:8b")
	if !client.Available() {
		t.Error("expected Available() to return true")
	}
}

func TestAvailableFalse(t *testing.T) {
	client := New("http://localhost:99999", "llama3:8b")
	if client.Available() {
		t.Error("expected Available() to return false")
	}
}

func TestSummarizePromptContainsContent(t *testing.T) {
	var capturedPrompt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req SummarizeRequest
		json.NewDecoder(r.Body).Decode(&req)
		capturedPrompt = req.Prompt
		json.NewEncoder(w).Encode(SummarizeResponse{Response: "summary"})
	}))
	defer server.Close()

	client := New(server.URL, "llama3:8b")
	defer client.Close()

	client.Summarize("my secret content here")
	if capturedPrompt == "" {
		t.Error("expected non-empty prompt")
	}
	// The prompt should contain the privacy instructions
	if !contains(capturedPrompt, "privacy filter") {
		t.Error("prompt should contain privacy filter instructions")
	}
	// The prompt should contain the content
	if !contains(capturedPrompt, "my secret content here") {
		t.Error("prompt should contain the content")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
