package protocol

import (
	"strings"
	"testing"
)

// A question's draft answer is signed with it, byte for byte, and only a question takes one.
func TestSignedQuestionPrefill(t *testing.T) {
	draft := "First line\nDraft with emoji 🦉 and trailing space "
	key, _ := NewKey()
	e, err := Sign(key, "hst_test", KindRequest, SignedRequest{ID: "req_draft", Type: RequestQuestion, Prefill: &draft})
	if err != nil {
		t.Fatal(err)
	}
	var decoded SignedRequest
	if err := e.Open(KindRequest, &key.PublicKey, &decoded); err != nil || decoded.Prefill == nil || *decoded.Prefill != draft {
		t.Fatalf("draft %v, %v", decoded.Prefill, err)
	}
	for _, bad := range []string{strings.Repeat("x", 8001), "nul\x00text", string([]byte{0xff})} {
		if ValidatePrefill(RequestQuestion, &bad) == nil {
			t.Fatal("invalid draft accepted")
		}
	}
	if ValidatePrefill(RequestApproval, &draft) == nil {
		t.Fatal("approval accepted question prefill")
	}
}
