package main

import (
	"strings"
	"testing"
)

// The store's file as this reads it: an entry's nested block (constraints) is not its end, and what follows the
// block is still the entry's. An anchor lost to a format this does not know is an error, never a shorter table:
// naive would refuse every server under it.
func TestEntries(t *testing.T) {
	list, version, err := entries([]byte(`
version_major: 43

# "CN=Root One"
trust_anchors {
  sha256_hex: "AA11"
  constraints: {
    sct_not_after_sec: 1
    permitted_dns_names: "example"
  }
  crs_root_id: 7
}

# "CN=Inter, O=One"
additional_certs {
  sha256_hex: "bb22"
  constraints {
    min_version: "1"
  }
  crs_root_id: 7
  enforce_anchor_expiry: true
  tls_trust_anchor: true
  trust_anchor_id: "\\x01"  # 1.2.3
}

# "CN=Of a trusted list"
additional_certs {
  sha256_hex: "cc33"
  eutl: true
}
`))
	if err != nil {
		t.Fatal(err)
	}
	if version != "43" || len(list) != 3 {
		t.Fatalf("version %q, %d entries", version, len(list))
	}
	root, anchor, other := list[0], list[1], list[2]
	if root.additional || root.fingerprint != "aa11" || root.rootID != "7" || root.subject != "CN=Root One" {
		t.Fatalf("the root: %+v", root)
	}
	if !anchor.additional || !anchor.tlsAnchor || anchor.rootID != "7" || anchor.fingerprint != "bb22" {
		t.Fatalf("the anchor after its nested block: %+v", anchor)
	}
	if !other.additional || other.tlsAnchor || other.rootID != "" {
		t.Fatalf("the certificate of a trusted list: %+v", other)
	}

	for name, text := range map[string]string{
		"an entry not closed":                  "additional_certs {\n  sha256_hex: \"aa\"\n",
		"an entry without a fingerprint":       "additional_certs {\n  tls_trust_anchor: true\n}\n",
		"an anchor mark inside a nested block": "additional_certs {\n  sha256_hex: \"aa\"\n  flags {\n    tls_trust_anchor: true\n  }\n}\n",
		"an anchor mark on a root":             "trust_anchors {\n  sha256_hex: \"aa\"\n  tls_trust_anchor: true\n}\n",
		"a block of another kind":              "new_anchors {\n  sha256_hex: \"aa\"\n  tls_trust_anchor: true\n}\n",
	} {
		_, _, err = entries([]byte(text))
		if err == nil {
			t.Errorf("%s: read without an error", name)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: an error that says nothing", name)
		}
	}
}
