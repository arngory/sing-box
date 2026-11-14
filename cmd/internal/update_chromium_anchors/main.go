// neko: the intermediates Chromium's root store takes as trust anchors, for the naive outbound's key pins
// (common/certificate/chromium_anchors_neko.go).
//
//	go run ./cmd/internal/update_chromium_anchors 158.0.8127.36
//
// The argument is the Chromium release the cronet-go library modules are built from (their const Version): the
// library carries that release's store and no later one. The store is read from Chromium's repository at the
// release's tag: root_store.textproto names the anchors, root_store.certs and additional.certs hold them.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
)

const storePath = "https://chromium.googlesource.com/chromium/src/+/refs/tags/%s/net/data/ssl/chrome_root_store/%s?format=TEXT"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: update_chromium_anchors CHROMIUM_VERSION")
		os.Exit(2)
	}
	err := update(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// file is a file of the store at the release's tag: the repository serves it in base64
func file(version string, name string) ([]byte, error) {
	response, err := http.Get(fmt.Sprintf(storePath, version, name))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s of Chromium %s: %s", name, version, response.Status)
	}
	return io.ReadAll(base64.NewDecoder(base64.StdEncoding, response.Body))
}

// entry is a trust_anchors or additional_certs block of root_store.textproto
type entry struct {
	subject     string
	additional  bool
	fingerprint string
	rootID      string
	tlsAnchor   bool
}

func entries(textproto []byte) ([]entry, string, error) {
	var (
		list    []entry
		current *entry
		// blocks open inside the entry's own (constraints { … }): their closing brace is not the entry's, and
		// their fields are not the entry's
		depth   int
		subject string
		version string
		// what the file says by plain count, against what was read: an entry or a field lost to a format this
		// does not know stops the generation, where it would leave an anchor out of the table without a word
		anchorLines int
	)
	scanner := bufio.NewScanner(bytes.NewReader(textproto))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, `# "`) && strings.HasSuffix(line, `"`) {
			subject = strings.TrimSuffix(strings.TrimPrefix(line, `# "`), `"`)
			continue
		}
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "tls_trust_anchor:") && strings.TrimSpace(strings.TrimPrefix(line, "tls_trust_anchor:")) == "true" {
			anchorLines++
		}
		switch {
		case line == "":
		case current == nil && strings.HasPrefix(line, "version_major:"):
			version = strings.TrimSpace(strings.TrimPrefix(line, "version_major:"))
		case line == "trust_anchors {" || line == "additional_certs {":
			if current != nil {
				return nil, "", fmt.Errorf("a block inside a block at %q", subject)
			}
			current = &entry{subject: subject, additional: line == "additional_certs {"}
		case current == nil:
			if strings.HasSuffix(line, "{") || line == "}" {
				return nil, "", fmt.Errorf("a block this does not know, outside the entries: %q", line)
			}
		case strings.HasSuffix(line, "{"):
			depth++
		case line == "}" && depth > 0:
			depth--
		case line == "}":
			if current.fingerprint == "" {
				return nil, "", fmt.Errorf("a block without sha256_hex at %q", current.subject)
			}
			list = append(list, *current)
			current = nil
		case depth == 0:
			name, value, _ := strings.Cut(line, ":")
			value = strings.Trim(strings.TrimSpace(value), `"`)
			switch strings.TrimSpace(name) {
			case "sha256_hex":
				current.fingerprint = strings.ToLower(value)
			case "crs_root_id":
				current.rootID = value
			case "tls_trust_anchor":
				current.tlsAnchor = value == "true"
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	if current != nil {
		return nil, "", fmt.Errorf("the block at %q is not closed", current.subject)
	}
	anchors := 0
	for _, e := range list {
		if e.tlsAnchor && !e.additional {
			return nil, "", fmt.Errorf("the root %q is marked tls_trust_anchor: the store's format has changed", e.subject)
		}
		if e.tlsAnchor {
			anchors++
		}
	}
	if anchors != anchorLines {
		return nil, "", fmt.Errorf("%d lines say tls_trust_anchor: true, %d entries were read with it: the store's format has changed", anchorLines, anchors)
	}
	return list, version, nil
}

// certificates by the SHA-256 of their encoding, as the textproto names them
func certificates(files ...[]byte) (map[string]*x509.Certificate, error) {
	found := make(map[string]*x509.Certificate)
	for _, rest := range files {
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			fingerprint := sha256.Sum256(block.Bytes)
			found[hex.EncodeToString(fingerprint[:])] = certificate
		}
	}
	return found, nil
}

func keyHash(certificate *x509.Certificate) string {
	hash := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func update(version string) error {
	textproto, err := file(version, "root_store.textproto")
	if err != nil {
		return err
	}
	rootsFile, err := file(version, "root_store.certs")
	if err != nil {
		return err
	}
	additionalFile, err := file(version, "additional.certs")
	if err != nil {
		return err
	}
	list, storeVersion, err := entries(textproto)
	if err != nil {
		return err
	}
	known, err := certificates(rootsFile, additionalFile)
	if err != nil {
		return err
	}
	// the roots by their crs_root_id: an intermediate names its root by it
	roots := make(map[string]*x509.Certificate)
	rootCount := 0
	for _, e := range list {
		if e.additional {
			continue
		}
		root := known[e.fingerprint]
		if root == nil {
			return fmt.Errorf("the root %q (%s) is not in root_store.certs", e.subject, e.fingerprint)
		}
		rootCount++
		if e.rootID == "" {
			continue
		}
		if roots[e.rootID] != nil {
			return fmt.Errorf("two roots with crs_root_id %s", e.rootID)
		}
		roots[e.rootID] = root
	}
	type anchor struct{ name, key, rootName, rootKey string }
	var anchors []anchor
	for _, e := range list {
		// the other additional certificates are of the EU's trusted lists (QWACs): never an end of a TLS chain
		if !e.additional || !e.tlsAnchor {
			continue
		}
		intermediate := known[e.fingerprint]
		if intermediate == nil {
			return fmt.Errorf("the anchor %q (%s) is not in additional.certs", e.subject, e.fingerprint)
		}
		root := roots[e.rootID]
		if root == nil {
			return fmt.Errorf("the anchor %q names the root %q, which the store does not have", e.subject, e.rootID)
		}
		// the store's word that the intermediate is of that root is not taken: the root's key has to have signed it
		err = intermediate.CheckSignatureFrom(root)
		if err != nil {
			return fmt.Errorf("the anchor %q is not signed by its root %q: %w", e.subject, root.Subject.CommonName, err)
		}
		anchors = append(anchors, anchor{intermediate.Subject.String(), keyHash(intermediate), root.Subject.String(), keyHash(root)})
	}
	if len(anchors) == 0 {
		return fmt.Errorf("Chromium %s: no intermediate is a TLS trust anchor: the store's format has changed", version)
	}
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].name < anchors[j].name })

	generated := strings.Builder{}
	generated.WriteString("// Code generated by 'go run ./cmd/internal/update_chromium_anchors " + version + "'. DO NOT EDIT.\n\n")
	generated.WriteString("package certificate\n\n")
	generated.WriteString("// ChromiumAnchorsVersion is the Chromium release whose root store (version " + storeVersion + ", " +
		fmt.Sprint(rootCount) + " roots) these are of.\n")
	generated.WriteString("const ChromiumAnchorsVersion = " + fmt.Sprintf("%q", version) + "\n\n")
	generated.WriteString("var chromiumIntermediateAnchors = []chromiumIntermediateAnchor{\n")
	for _, a := range anchors {
		generated.WriteString(fmt.Sprintf("\t// %s, of %s\n\t{key: %q, rootKey: %q},\n", a.name, a.rootName, a.key, a.rootKey))
	}
	generated.WriteString("}\n")
	return os.WriteFile("common/certificate/chromium_anchors_neko_generated.go", []byte(generated.String()), 0o644)
}
