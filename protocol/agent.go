package protocol

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// Agent message categories.
const (
	CategoryInfo      = "info"
	CategoryProgress  = "progress"
	CategoryCompleted = "completed"
	CategoryFailed    = "failed"
	CategoryAttention = "attention"
	CategoryApproval  = "approval"
	CategoryQuestion  = "question"
	CategoryWarning   = "warning"
)

// Categories are the known event categories.
var Categories = map[string]bool{
	CategoryInfo: true, CategoryProgress: true, CategoryCompleted: true, CategoryFailed: true,
	CategoryAttention: true, CategoryApproval: true, CategoryQuestion: true, CategoryWarning: true,
}

// Known providers.
const (
	ProviderClaudeCode = "claude-code"
	ProviderCodex      = "codex"
	ProviderPi         = "pi"
	ProviderOpenCode   = "opencode"
)

// Session statuses.
const (
	SessionActive = "active"
	SessionIdle   = "idle"
	SessionEnded  = "ended"
)

// Input modes summarise what a reply will do right now: wait for the agent's next agentio tool call, or nothing.
const (
	InputQueue       = "queue"
	InputUnavailable = "unavailable"
)

// Command states. They only move forward, in this order, until a terminal state.
const (
	CommandReceived  = "received"
	CommandPending   = "pending"
	CommandDelivered = "delivered"
	CommandFailed    = "failed"
	CommandExpired   = "expired"
	CommandCanceled  = "canceled"
)

// CommandStateRank orders non-terminal states; terminal states rank highest.
var CommandStateRank = map[string]int{
	CommandReceived:  0,
	CommandPending:   1,
	CommandDelivered: 10,
	CommandFailed:    10,
	CommandExpired:   10,
	CommandCanceled:  10,
}

// CommandTerminal reports whether a state is final.
func CommandTerminal(state string) bool { return CommandStateRank[state] >= 10 }

// Request types and statuses.
const (
	RequestApproval = "approval"
	RequestQuestion = "question"

	RequestPending  = "pending"
	RequestApproved = "approved"
	RequestRejected = "rejected"
	RequestAnswered = "answered"
	RequestExpired  = "expired"
	RequestCanceled = "canceled"

	DecisionApprove = "approve"
	DecisionReject  = "reject"
	DecisionAnswer  = "answer"
)

// RequestTerminal reports whether a request status is final.
func RequestTerminal(status string) bool { return status != RequestPending }

// Machine is what a host says about itself in updates.
type Machine struct {
	Name    string `json:"name"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version"`
}

// Project is an integrated project on a host, as its bridge records it.
type Project struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Path         string   `json:"path"` // display path, e.g. ~/pro/x
	Agents       []string `json:"agents"`
	Created      int64    `json:"created"`
	LastActivity int64    `json:"last_activity"`
	Seq          int64    `json:"seq"`
}

// Session is one agent session, as its bridge records it.
type Session struct {
	ID           string `json:"id"`
	Project      string `json:"project"`
	Provider     string `json:"provider"`
	NativeID     string `json:"native_id"`
	Title        string `json:"title"`
	Status       string `json:"status"`
	Input        string `json:"input"`
	InputReason  string `json:"input_reason"`
	Remote       bool   `json:"remote"` // remote control: the user drives the session from a paired browser
	Created      int64  `json:"created"`
	LastActivity int64  `json:"last_activity"`
	Seq          int64  `json:"seq"`
}

// Item types.
const (
	ItemEvent   = "event"
	ItemRequest = "request"
	ItemCommand = "command"
)

// Item is one entry of a session's timeline. Pos orders the timeline and never changes; Seq changes with its state.
// Exactly one of Event, Request and Command is set, as Type says.
type Item struct {
	ID      string       `json:"id"`
	Session string       `json:"session"`
	Type    string       `json:"type"`
	Time    int64        `json:"time"`
	Pos     int64        `json:"pos"`
	Seq     int64        `json:"seq"`
	Event   *EventItem   `json:"event,omitempty"`
	Request *RequestItem `json:"request,omitempty"`
	Command *CommandItem `json:"command,omitempty"`
}

// EventItem is a notification from an agent session.
type EventItem struct {
	Category string `json:"category"`
	Title    string `json:"title"`
	Message  string `json:"message"`
}

// RequestItem is an approval or question: the host-signed request (kind request), whose payload hash a response
// binds, and its current status.
type RequestItem struct {
	Envelope *Envelope       `json:"envelope"`
	Status   string          `json:"status"`
	Response *ResponseRecord `json:"response,omitempty"`
}

// ResponseRecord is the answer that resolved a request.
type ResponseRecord struct {
	Decision string `json:"decision"`
	Text     string `json:"text,omitempty"`
	Time     int64  `json:"time"`
	Signer   string `json:"signer"`
	Device   string `json:"device,omitempty"` // name of the signer
}

// CommandItem is a message from the user to an agent session and how far it got.
type CommandItem struct {
	Text        string `json:"text"`
	Created     int64  `json:"created"`
	Expires     int64  `json:"expires"`
	Signer      string `json:"signer"`
	Device      string `json:"device,omitempty"` // name of the signer
	State       string `json:"state"`
	StateDetail string `json:"state_detail,omitempty"`
	Delivery    string `json:"delivery,omitempty"`
	Updated     int64  `json:"updated"`
}

// Deletion records a deleted project or session, so syncing devices remove it too.
type Deletion struct {
	Project string `json:"project,omitempty"`
	Session string `json:"session,omitempty"`
	Seq     int64  `json:"seq"`
}

// AwayState is the newest away setting and the effective away state.
type AwayState struct {
	Mode string `json:"mode"` // auto, on, off
	Time int64  `json:"time"` // when the setting was made
	Away bool   `json:"away"`
}

// Update is everything a bridge tells a browser (kind update, docs/api.md §10.2). Every field but Host, Time and
// Epoch is optional.
type Update struct {
	Host     string     `json:"host"`
	Time     int64      `json:"time"`
	Epoch    string     `json:"epoch"`
	Reply    string     `json:"reply,omitempty"` // the RPC ID this answers; live updates have none
	Machine  *Machine   `json:"machine,omitempty"`
	Projects []Project  `json:"projects,omitempty"`
	Sessions []Session  `json:"sessions,omitempty"`
	Items    []Item     `json:"items,omitempty"`
	Deleted  []Deletion `json:"deleted,omitempty"`
	Settings *Envelope  `json:"settings,omitempty"` // the newest settings snapshot (kind settings)
	Away     *AwayState `json:"away,omitempty"`
	Full     bool       `json:"full,omitempty"`     // sync replies: a full snapshot that replaces the device's mirror of this host
	Cursor   int64      `json:"cursor,omitempty"`   // sync replies: the highest seq included
	More     bool       `json:"more,omitempty"`     // sync replies: sync again from Cursor for the rest
	HasMore  bool       `json:"has_more,omitempty"` // timeline replies: older items exist
}

// MaxSyncReply is roughly how many payload bytes one sync reply carries before it sets More.
const MaxSyncReply = 256 << 10

// Relay message types (docs/api.md §7).
const (
	RelayHello    = "hello"
	RelayFrame    = "frame"
	RelayRelayed  = "relayed"
	RelayPresence = "presence"
	RelayPing     = "ping"
	RelayPong     = "pong"
)

// Relay results.
const (
	RelayDelivered = "delivered"
	RelayOffline   = "offline"
	RelayRefused   = "refused"
)

// MaxRelayMessage is the largest relay WebSocket message, in bytes.
const MaxRelayMessage = 1 << 20

// RelayMessage is one WebSocket message on a relay socket, in either direction.
type RelayMessage struct {
	Type   string         `json:"type"`
	Frame  *SealedFrame   `json:"frame,omitempty"`
	Push   *SealedFrame   `json:"push,omitempty"`   // client → server, hosts only
	Host   string         `json:"host,omitempty"`   // hello (host socket), presence
	Device string         `json:"device,omitempty"` // hello (device socket)
	Hosts  []HostPresence `json:"hosts,omitempty"`  // hello (device socket)
	Online *bool          `json:"online,omitempty"` // presence
	ID     string         `json:"id,omitempty"`     // relayed: the frame ID
	To     string         `json:"to,omitempty"`     // relayed
	Result string         `json:"result,omitempty"` // relayed
	Code   string         `json:"code,omitempty"`   // relayed, refused
	Error  string         `json:"error,omitempty"`  // relayed, refused
}

// HostPresence says whether a host has a live relay connection.
type HostPresence struct {
	Host   string `json:"host"`
	Online bool   `json:"online"`
}

// HostInfo is what the server knows about a machine: keys, never names.
type HostInfo struct {
	ID      string `json:"id"`
	Key     string `json:"key"`
	EncKey  string `json:"enc_key"`
	Online  bool   `json:"online"`
	Created int64  `json:"created"`
}

// DeviceInfo is what the server knows about a paired browser: keys and links, never names.
type DeviceInfo struct {
	ID              string   `json:"id"`
	Key             string   `json:"key"`
	SensitiveKey    string   `json:"sensitive_key"`
	EncKey          string   `json:"enc_key"`
	SensitiveOrigin string   `json:"sensitive_origin"`
	Hosts           []string `json:"hosts"`
	Created         int64    `json:"created"`
}

// WebPushSubscription is a browser's push subscription for its device.
type WebPushSubscription struct {
	Endpoint string `json:"endpoint"`
	Auth     string `json:"auth"`
	P256dh   string `json:"p256dh"`
}

// Pairing statuses.
const (
	PairPending   = "pending"
	PairClaimed   = "claimed"
	PairConfirmed = "confirmed"
	PairRejected  = "rejected"
	PairExpired   = "expired"
)

// PairStart registers a pairing; the CLI chooses the ID and keeps the secret K to itself.
type PairStart struct {
	ID         string `json:"id"`
	HostKey    string `json:"host_key"`
	HostEncKey string `json:"host_enc_key"`
}

// PairStarted is returned by POST /api/v1/pair and /claim: the caller's poll secret.
type PairStarted struct {
	ID      string `json:"id,omitempty"`
	Secret  string `json:"secret"`
	Expires int64  `json:"expires"`
}

// PairClaim is the device's half of a pairing. SealedName is the device name sealed with K; Device is derived by the
// server for the host's convenience.
type PairClaim struct {
	Device                string `json:"device,omitempty"`
	DeviceKey             string `json:"device_key"`
	DeviceSensitiveKey    string `json:"device_sensitive_key"`
	DeviceSensitiveOrigin string `json:"device_sensitive_origin"`
	DeviceEncKey          string `json:"device_enc_key"`
	SealedName            string `json:"sealed_name"`
	MAC                   string `json:"mac"`
}

// MaxSealedName is the longest sealed device name the server accepts, in characters.
const MaxSealedName = 512

// PairHost is what the device learns about the host from the server; it trusts only the signed confirmation.
type PairHost struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	EncKey string `json:"enc_key"`
}

// PairStatus is returned when polling a pairing. Claim is for the host; the rest for the device. Confirm is the
// host's pair envelope sealed with K.
type PairStatus struct {
	Status   string     `json:"status"`
	Claim    *PairClaim `json:"claim,omitempty"`
	Confirm  string     `json:"confirm,omitempty"`
	Host     *PairHost  `json:"host,omitempty"`
	Username string     `json:"username,omitempty"`
}

// PairConfirm is the host's confirmation: a SignedPair envelope sealed with K.
type PairConfirm struct {
	Secret  string `json:"secret"`
	Confirm string `json:"confirm"`
}

// PairConfirmResult is returned to the host; Token only for a new machine.
type PairConfirmResult struct {
	HostID   string `json:"host_id"`
	Username string `json:"username"`
	Token    string `json:"token,omitempty"`
}

// DeriveID derives deterministic session/project IDs so a host can only address its own resources.
func DeriveID(prefix string, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return prefix + strings.ToLower(enc[:20])
}

// SessionID derives a session ID.
func SessionID(hostID, provider, nativeID string) string {
	return DeriveID("ses_", hostID, provider, nativeID)
}

// ProjectID derives a project ID.
func ProjectID(hostID, pathHash string) string {
	return DeriveID("prj_", hostID, pathHash)
}
