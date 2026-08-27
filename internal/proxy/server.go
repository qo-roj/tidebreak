// Package proxy implements the Tidebreak HTTP reverse proxy.
// It listens on localhost, intercepts LLM API requests, routes them through
// the classifier/redactor/router, and forwards to the upstream cloud API.
//
// Local connection: plain HTTP (no TLS needed for localhost).
// Upstream connection: HTTPS (TLS terminated by cloud provider).
package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/earl-sid/tidebreak/internal/audit"
	"github.com/earl-sid/tidebreak/internal/route"
)

// UpstreamRoutes maps path prefixes to upstream API hosts.
var UpstreamRoutes = map[string]string{
	"/anthropic": "api.anthropic.com",
	"/openai":    "api.openai.com",
	"/xai":       "api.x.ai",
}

// Server is the Tidebreak proxy server.
type Server struct {
	Router   *route.Router
	AuditLog *audit.Log
	Port     int
}

// New creates a proxy Server.
func New(router *route.Router, auditLog *audit.Log, port int) *Server {
	return &Server{
		Router:   router,
		AuditLog: auditLog,
		Port:     port,
	}
}

// Start begins listening on localhost:port. Blocks until the server stops.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleProxy)

	addr := fmt.Sprintf("127.0.0.1:%d", s.Port)
	log.Printf("Tidebreak proxy listening on %s", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return server.ListenAndServe()
}

// handleProxy is the main request handler.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Identify the agent from the custom header
	agent := r.Header.Get("X-Tidebreak-Agent")
	if agent == "" {
		agent = "unknown"
	}

	// Determine the upstream provider from the path prefix
	upstreamHost, provider := s.resolveUpstream(r.URL.Path)
	if upstreamHost == "" {
		http.Error(w, "unknown API path prefix", http.StatusBadGateway)
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// Process the request through the router (classify, redact, route)
	ctx, modifiedBody, blocked, err := s.Router.ProcessRequest(body, agent, provider)
	if err != nil {
		// Fail-closed: do not forward unredacted content on router error
		http.Error(w, "gateway processing error", http.StatusBadGateway)
		return
	}

	if blocked {
		// Some content was blocked — the modified body contains block messages
		// but we still forward so the agent gets a response
		log.Printf("request from agent=%s had blocked content", agent)
	}

	// Forward to upstream
	upstreamReq, err := http.NewRequest(r.Method, "https://"+upstreamHost+r.URL.Path, strings.NewReader(string(modifiedBody)))
	if err != nil {
		http.Error(w, "creating upstream request", http.StatusInternalServerError)
		return
	}

	// Copy headers (except Tidebreak-specific and hop-by-hop headers)
	for k, v := range r.Header {
		if k == "X-Tidebreak-Agent" || k == "Host" || k == "Content-Length" {
			continue
		}
		upstreamReq.Header[k] = v
	}
	upstreamReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(modifiedBody)))

	// Send to upstream
	resp, err := http.DefaultClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Check if this is a streaming response (SSE)
	contentType := resp.Header.Get("Content-Type")
	isStreaming := strings.Contains(contentType, "text/event-stream")

	if isStreaming {
		s.handleStreamingResponse(w, resp, ctx)
	} else {
		s.handleBatchResponse(w, resp, ctx)
	}
}

// handleBatchResponse handles non-streaming responses.
func (s *Server) handleBatchResponse(w http.ResponseWriter, resp *http.Response, ctx *route.RequestContext) {
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "reading upstream response", http.StatusBadGateway)
		return
	}

	// Reverse-map tokens in the response using the per-request context
	processed := s.Router.ProcessResponse(ctx, respBody)

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(processed)))
	w.WriteHeader(resp.StatusCode)
	w.Write(processed)
}

// handleStreamingResponse handles SSE streaming responses.
// It pipes chunks through the stream redactor for token reverse-mapping.
// The StreamRedactor is created once per response to maintain the boundary
// buffer across chunks.
func (s *Server) handleStreamingResponse(w http.ResponseWriter, resp *http.Response, ctx *route.RequestContext) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback to batch mode if flushing not supported
		s.handleBatchResponse(w, resp, ctx)
		return
	}

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	// Create one StreamRedactor per response — the boundary buffer
	// must persist across chunks to handle tokens split at boundaries
	sr := s.Router.NewStreamRedactor(ctx)

	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			var processed []byte
			if sr != nil {
				processed = s.Router.ProcessStreamChunk(ctx, sr, chunk)
			} else {
				processed = chunk
			}
			w.Write(processed)
			flusher.Flush()
		}
		if err != nil {
			break
		}
	}

	// Flush any remaining buffer
	if sr != nil {
		remaining := sr.Flush()
		if len(remaining) > 0 {
			w.Write(remaining)
			flusher.Flush()
		}
	}
}

// resolveUpstream determines the upstream API host from the request path.
func (s *Server) resolveUpstream(path string) (host string, provider string) {
	for prefix, host := range UpstreamRoutes {
		if strings.HasPrefix(path, prefix) {
			return host, strings.TrimPrefix(prefix, "/")
		}
	}
	return "", ""
}

// HealthCheck is a simple handler for liveness checks.
func (s *Server) HealthCheck(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status": "ok",
		"port":   s.Port,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}