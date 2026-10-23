package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"agentio.sh/protocol"
)

// APIError is an HTTP error: its status, a stable machine-readable code and a message for people.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string { return e.Message }

// NewError returns an API error. Extensions make their own with codes that don't collide with the core's.
func NewError(status int, code, msg string) *APIError {
	return &APIError{Status: status, Code: code, Message: msg}
}

// Wrap returns a copy of e with a detail added to its message.
func (e *APIError) Wrap(format string, args ...any) *APIError {
	return &APIError{Status: e.Status, Code: e.Code, Message: e.Message + ": " + fmt.Sprintf(format, args...)}
}

var (
	ErrBadRequest          = NewError(400, "bad_request", "Invalid request")
	ErrBadJSON             = NewError(400, "bad_json", "The request body isn't valid JSON")
	errBadUsername         = NewError(400, "bad_username", "Invalid username")
	errBadPassword         = NewError(400, "bad_password", "Wrong or invalid password")
	ErrUnauthorized        = NewError(401, "unauthorized", "Missing or invalid credentials")
	errBadLogin            = NewError(401, "bad_login", "Wrong username or password")
	ErrForbidden           = NewError(403, "forbidden", "You don't have access to this")
	errHostTokenNotAllowed = NewError(403, "machine_token", "A machine's token can't do this")
	errSignupDisabled      = NewError(403, "signup_off", "Sign-up is off on this server")
	errNoPasswords         = NewError(403, "no_passwords", "Accounts on this server have no passwords")
	ErrNotFound            = NewError(404, "not_found", "Not found")
	errNoWebApp            = NewError(404, "no_web_pages", "This is an agentio API server; it serves no web pages")
	errUserExists          = NewError(409, "username_taken", "That username is taken")
	errPairingClaimed      = NewError(409, "pairing_used", "This pairing has already been used")
	errOtherAccount        = NewError(409, "other_account", "This computer or browser is linked to another account")
	errHostPaired          = NewError(409, "already_paired", "This computer is already paired; run `agentio devices add` on it to add a browser")
	errHostKeyChanged      = NewError(409, "key_changed", "This computer's encryption key doesn't match the one it was paired with")
	errDeviceKeyChanged    = NewError(409, "key_changed", "This browser's keys don't match the ones it was paired with; unpair it first")
	errNotPaired           = NewError(409, "not_paired", "This machine and this browser aren't paired")
	errExpired             = NewError(410, "expired", "This pairing expired; start again")
	ErrTooManyRequests     = NewError(429, "slow_down", "Too many requests; slow down")
	errTooManySockets      = NewError(429, "too_many_connections", "Too many open connections for this browser or account; close some tabs")
	errTooManyPairings     = NewError(429, "slow_down", "Too many pairings in progress; try again in a few minutes")
	ErrInternal            = NewError(500, "internal", "Something went wrong on the server")
	errPushUnavailable     = NewError(500, "push_off", "Web Push isn't set up on this server")
)

// WriteJSON writes v as a JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	e, ok := err.(*APIError)
	if !ok {
		e = ErrInternal
	}
	if e.Status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	WriteJSON(w, e.Status, protocol.ErrorResponse{Code: e.Code, Error: e.Message})
}
