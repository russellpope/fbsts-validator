package trustpolicy

import (
	"testing"
)

func TestClassifyClaims(t *testing.T) {
	in := map[string]interface{}{
		"iss":            "https://idp.example",
		"sub":            "user1",
		"aud":            "purestorage",
		"groups":         []interface{}{"eng", "security"},
		"exp":            float64(1713300000),
		"email_verified": true,
		"raw":            map[string]interface{}{"x": 1},
	}
	got := ClassifyClaims(in)

	want := map[string]Kind{
		"iss":            SingleString,
		"sub":            SingleString,
		"aud":            SingleString,
		"groups":         MultiString,
		"exp":            SingleNumber,
		"email_verified": SingleBool,
		"raw":            Other,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d claims, want %d", len(got), len(want))
	}
	for _, c := range got {
		if want[c.Name] != c.Kind {
			t.Errorf("claim %q kind = %v, want %v", c.Name, c.Kind, want[c.Name])
		}
	}
}

func TestClassifyClaims_StableOrder(t *testing.T) {
	in := map[string]interface{}{"z": "1", "a": "2", "m": "3"}
	got := ClassifyClaims(in)
	wantOrder := []string{"a", "m", "z"}
	for i, c := range got {
		if c.Name != wantOrder[i] {
			t.Errorf("position %d = %q, want %q", i, c.Name, wantOrder[i])
		}
	}
}
