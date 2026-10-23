// Package protocol defines the wire types shared by the agentio server, CLI and local bridge.
// docs/api.md is the human-readable contract; these types are its canonical encoding.
package protocol

// ErrorResponse is the body of every API error; the HTTP status is the response's own.
type ErrorResponse struct {
	Code  string `json:"code"`  // stable and machine-readable, e.g. "bad_request"
	Error string `json:"error"` // for people
}
