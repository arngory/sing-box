package boxdd

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/service/powerreport"

	"google.golang.org/grpc/peer"
)

func TestNekoLogRedactorAndOwnerClear(t *testing.T) {
	savedOptions := activeOptions
	savedWorkingDir := workingDirectory
	savedCwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(savedCwd)
		activeOptions = savedOptions
		workingDirectory = savedWorkingDir
	}()

	root := t.TempDir()
	workingDirectory = root
	activeOptions = Options{
		Names: DefaultNames(),
		LogRedactor: func(s string) string {
			s = strings.ReplaceAll(s, "topsecret-pass", "<redacted>")
			s = strings.ReplaceAll(s, "secret.node.example", "<node>")
			return s
		},
	}

	d := &Daemon{
		ctx:                     context.Background(),
		logger:                  log.StdLogger(),
		powerManager:            powerreport.NewManager(),
		rootDirectory:           root,
		runtimeWorkingDirectory: root,
		startedService: daemon.NewStartedService(daemon.ServiceOptions{
			Context:     context.Background(),
			LogMaxLines: 64,
			LogRedactor: activeOptions.LogRedactor,
		}),
	}
	defer d.startedService.Close()

	// 1. Live log ring scrubs secrets and node hosts.
	d.startedService.WriteMessage(log.LevelInfo, `connect to secret.node.example password="topsecret-pass"`)
	entries := d.startedService.SavedLog()
	if len(entries) != 1 {
		t.Fatalf("expected 1 saved log line, got %d", len(entries))
	}
	if strings.Contains(entries[0].Message, "topsecret-pass") || strings.Contains(entries[0].Message, "secret.node.example") {
		t.Fatalf("secret leaked in log ring: %q", entries[0].Message)
	}

	// 2. Crash/OOM report read and zip export scrub go.log and native.log.
	userID := "user-a"
	crashDir := filepath.Join(userWorkingDirectory(userID), crashReportsDirectoryName, "2026-11-26-01")
	if err := os.MkdirAll(crashDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crashDir, ownerMarkerFileName), []byte(userID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crashDir, goLogFileName), []byte("dial secret.node.example topsecret-pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveOwner(userID, 1); err != nil {
		t.Fatal(err)
	}

	ds := &desktopService{daemon: d}
	ctxUserA := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: &peerAuthInfo{identity: peerIdentity{UserID: userID, SessionID: 1}},
	})
	readResp, err := ds.ReadCrashReport(ctxUserA, &CrashReportRequest{Name: "2026-11-26-01"})
	if err != nil {
		t.Fatalf("ReadCrashReport: %v", err)
	}
	if len(readResp.Files) != 1 || strings.Contains(readResp.Files[0].Content, "topsecret-pass") || strings.Contains(readResp.Files[0].Content, "secret.node.example") {
		t.Fatalf("ReadCrashReport leaked secret: %+v", readResp.Files)
	}

	archive, err := ds.ExportCrashReport(ctxUserA, &CrashReportExportRequest{Name: "2026-11-26-01", WithLog: true})
	if err != nil {
		t.Fatalf("ExportCrashReport: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(archive.Data), int64(len(archive.Data)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	foundLog := false
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/"+goLogFileName) || f.Name == goLogFileName {
			foundLog = true
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "topsecret-pass") || strings.Contains(string(body), "secret.node.example") {
				t.Fatalf("ExportCrashReport zip leaked secret: %q", string(body))
			}
		}
	}
	if !foundLog {
		t.Fatal("go.log missing from exported crash report archive")
	}

	// 3. Owner take-over clears the in-memory log ring.
	if err := ds.takeOverServiceLocked(peerIdentity{UserID: "user-b", SessionID: 2}, userID); err != nil {
		t.Fatalf("takeOverServiceLocked: %v", err)
	}
	if got := len(d.startedService.SavedLog()); got != 0 {
		t.Fatalf("expected log ring cleared on owner take-over, got %d entries", got)
	}
}
