package protocol

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// ValidatePrefill preserves drafts exactly. Only questions accept an optional UTF-8 draft,
// including an empty draft, of at most 8000 Unicode code points and with no NUL.
func ValidatePrefill(typ string, prefill *string) error {
	if prefill == nil {
		return nil
	}
	if typ != RequestQuestion {
		return fmt.Errorf("prefill is only valid for questions")
	}
	if !utf8.ValidString(*prefill) || utf8.RuneCountInString(*prefill) > 8000 || strings.ContainsRune(*prefill, 0) {
		return fmt.Errorf("prefill must be valid UTF-8, at most 8000 characters, without NUL")
	}
	return nil
}
