package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"time"

	"agentio.sh/server/internal/store"
)

const idAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomString returns n random characters from idAlphabet.
func randomString(n int) string {
	return randomFrom(idAlphabet, n)
}

func randomFrom(alphabet string, n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

// NewToken returns a new token of an account: a public ID (tok_…) and a secret (aio_…), last used now.
func NewToken(userID, kind, label string, expires int64) *store.Token {
	return &store.Token{ID: newID("tok_"), Token: "aio_" + randomString(32), UserID: userID, Kind: kind, Label: label, LastAccess: time.Now().Unix(), Expires: expires}
}

// SignInToken returns the user token a person's sign-in issues to a browser: it expires after 30 days.
func SignInToken(userID, label string) *store.Token {
	return NewToken(userID, store.TokenUser, label, time.Now().Add(30*24*time.Hour).Unix())
}

func newID(prefix string) string {
	return prefix + strings.ToLower(randomFrom("abcdefghijklmnopqrstuvwxyz0123456789", 20))
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
