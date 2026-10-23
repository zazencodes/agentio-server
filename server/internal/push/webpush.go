// Package push delivers Web Push messages to browsers.
package push

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

// ErrUnregistered means the push subscription is permanently invalid and should be removed.
var ErrUnregistered = errors.New("push subscription unregistered")

// WebPush sends browser notifications with VAPID.
type WebPush struct {
	public, private, subscriber string
}

// NewWebPush configures VAPID keys.
func NewWebPush(public, private, email string) *WebPush {
	if email == "" {
		email = "webpush@agentio.sh"
	}
	return &WebPush{public: public, private: private, subscriber: email}
}

// PublicKey returns the VAPID public key for clients.
func (w *WebPush) PublicKey() string { return w.public }

// Send encrypts and delivers a payload to a browser subscription.
func (w *WebPush) Send(ctx context.Context, endpoint, auth, p256dh string, payload []byte, ttl time.Duration) error {
	resp, err := webpush.SendNotificationWithContext(ctx, payload, &webpush.Subscription{Endpoint: endpoint, Keys: webpush.Keys{Auth: auth, P256dh: p256dh}},
		&webpush.Options{Subscriber: w.subscriber, VAPIDPublicKey: w.public, VAPIDPrivateKey: w.private, TTL: int(ttl.Seconds()), Urgency: webpush.UrgencyHigh})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound:
		return ErrUnregistered
	case resp.StatusCode >= 300:
		return fmt.Errorf("webpush: %d", resp.StatusCode)
	}
	return nil
}

// GenerateVAPIDKeys returns a new (private, public) VAPID key pair.
func GenerateVAPIDKeys() (string, string, error) {
	return webpush.GenerateVAPIDKeys()
}
