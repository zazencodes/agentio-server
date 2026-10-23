package protocol

import (
	"strings"
	"testing"
)

func TestSignedQuestionPrefill(t *testing.T) {
	draft := "First line\nDraft with emoji 🦉 and trailing space "
	if err := ValidatePrefill(RequestQuestion, &draft); err != nil {
		t.Fatal(err)
	}
	key, _ := NewKey()
	r := SignedRequest{ID: "req_draft", Type: RequestQuestion, Prefill: &draft}
	e, err := Sign(key, "hst_test", KindRequest, r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded SignedRequest
	if err := e.Open(KindRequest, &key.PublicKey, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Prefill == nil || *decoded.Prefill != draft {
		t.Fatal("draft was changed")
	}
	original := e.PayloadHash()
	changed := "changed"
	r.Prefill = &changed
	e, _ = Sign(key, "hst_test", KindRequest, r)
	if e.PayloadHash() == original {
		t.Fatal("answer hash did not bind draft")
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
