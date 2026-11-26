package boxdd

// niko: manifest verification for portable ZIP -> Program Files installation (slice 14).

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// Structured exit codes returned by "service install" on Windows so the desktop UI
	// can render precise diagnostics after UAC elevation.
	InstallExitNotElevated     = 10
	InstallExitInvalidLayout   = 11
	InstallExitSignatureFailed = 12
	InstallExitManifestFailed  = 13
	InstallExitTargetBusy      = 14
	InstallExitInvalidSource   = 15

	installManifestRelativePath = "resources/files.sha256"
	maxInstallManifestSize      = 4 << 20   // 4 MiB
	maxInstallTotalBytes        = 512 << 20 // 512 MiB cap against disk exhaustion during staging
)

type installExitError struct {
	code int
	err  error
}

func (e *installExitError) Error() string {
	return e.err.Error()
}

func (e *installExitError) Unwrap() error {
	return e.err
}

type manifestEntry struct {
	relSlash string
	relKey   string
	sum      []byte
}

// verifyInstallManifest checks that:
//  1. <root>/resources/files.sha256 exists and its raw SHA-256 equals expectedManifestSHA256;
//  2. every listed file exists under root and matches its recorded SHA-256;
//  3. no unexpected extra files exist under root outside the manifest, the manifest itself,
//     and resources/daemon/<daemonExe> (which carries expectedManifestSHA256 and is verified by Authenticode).
func verifyInstallManifest(root string, expectedManifestSHA256 string, daemonExe string) error {
	expectedBytes, err := hex.DecodeString(expectedManifestSHA256)
	if err != nil || len(expectedBytes) != sha256.Size {
		return E.New("invalid expected install manifest SHA-256")
	}

	manifestPath := filepath.Join(root, filepath.FromSlash(installManifestRelativePath))
	manifestData, err := readFileBounded(manifestPath, maxInstallManifestSize)
	if err != nil {
		return E.Cause(err, "read install manifest")
	}
	actualManifestSum := sha256.Sum256(manifestData)
	if subtle.ConstantTimeCompare(actualManifestSum[:], expectedBytes) != 1 {
		return E.New("install manifest SHA-256 mismatch")
	}

	list, err := parseInstallManifest(manifestData, daemonExe)
	if err != nil {
		return err
	}
	entries := make(map[string][]byte, len(list))
	for _, item := range list {
		entries[item.relKey] = item.sum
	}

	selfDaemonRel := strings.ToLower(path.Join("resources", "daemon", daemonExe))
	manifestRel := strings.ToLower(installManifestRelativePath)

	seen := make(map[string]bool, len(entries))
	err = filepath.WalkDir(root, func(fullPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return E.New("unexpected symlink in staged installation: ", fullPath)
		}
		rel, err := filepath.Rel(root, fullPath)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		relKey := strings.ToLower(relSlash)
		if relKey == manifestRel || relKey == selfDaemonRel {
			return nil
		}
		wantSum, listed := entries[relKey]
		if !listed {
			return E.New("unexpected file not listed in install manifest: ", relSlash)
		}
		gotSum, err := sha256File(fullPath)
		if err != nil {
			return E.Cause(err, "hash staged file ", relSlash)
		}
		if subtle.ConstantTimeCompare(gotSum[:], wantSum) != 1 {
			return E.New("SHA-256 mismatch for staged file: ", relSlash)
		}
		seen[relKey] = true
		return nil
	})
	if err != nil {
		return err
	}
	for relKey := range entries {
		if !seen[relKey] {
			return E.New("missing file listed in install manifest: ", relKey)
		}
	}
	return nil
}

func parseInstallManifest(data []byte, daemonExe string) ([]manifestEntry, error) {
	seen := make(map[string]bool)
	var entries []manifestEntry
	selfDaemonRel := strings.ToLower(path.Join("resources", "daemon", daemonExe))
	manifestRel := strings.ToLower(installManifestRelativePath)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		if len(line) < 67 || (line[64] != ' ' && line[64] != '\t') {
			return nil, E.New("malformed install manifest line ", lineNum)
		}
		sumHex := line[:64]
		sum, err := hex.DecodeString(sumHex)
		if err != nil || len(sum) != sha256.Size {
			return nil, E.New("invalid SHA-256 on install manifest line ", lineNum)
		}
		relRaw := strings.TrimLeft(line[64:], " \t")
		relRaw = strings.TrimPrefix(relRaw, "*")
		relSlash := strings.ReplaceAll(relRaw, `\`, "/")
		if relSlash == "" || strings.HasPrefix(relSlash, "/") || strings.ContainsAny(relSlash, `:*?"<>|`) || hasControlChar(relSlash) {
			return nil, E.New("invalid relative path on install manifest line ", lineNum)
		}
		cleaned := path.Clean(relSlash)
		if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != relSlash {
			return nil, E.New("non-canonical path on install manifest line ", lineNum)
		}
		for _, segment := range strings.Split(cleaned, "/") {
			if segment == "" || segment == "." || segment == ".." || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") || isWindowsReservedName(segment) {
				return nil, E.New("unsafe path component on install manifest line ", lineNum)
			}
		}
		key := strings.ToLower(cleaned)
		if key == manifestRel || key == selfDaemonRel {
			return nil, E.New("reserved self-referential path in install manifest: ", cleaned)
		}
		if seen[key] {
			return nil, E.New("duplicate path in install manifest: ", cleaned)
		}
		seen[key] = true
		entries = append(entries, manifestEntry{
			relSlash: cleaned,
			relKey:   key,
			sum:      sum,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, E.Cause(err, "scan install manifest")
	}
	if len(entries) == 0 {
		return nil, E.New("install manifest is empty")
	}
	return entries, nil
}

func readFileBounded(filePath string, limit int64) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, E.New("file exceeds maximum allowed size")
	}
	return data, nil
}

func sha256File(filePath string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	file, err := os.Open(filePath)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return zero, err
	}
	var sum [sha256.Size]byte
	hasher.Sum(sum[:0])
	return sum, nil
}
