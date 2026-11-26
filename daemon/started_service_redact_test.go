package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
)

func TestStartedServiceLogRedactor(t *testing.T) {
	svc := NewStartedService(ServiceOptions{
		Context:     context.Background(),
		LogMaxLines: 16,
		LogRedactor: func(s string) string {
			return strings.ReplaceAll(s, "hunter2", "<redacted>")
		},
	})
	defer svc.Close()

	svc.WriteMessage(log.LevelInfo, `dial with password="hunter2"`)
	saved := svc.SavedLog()
	if len(saved) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(saved))
	}
	if strings.Contains(saved[0].Message, "hunter2") {
		t.Fatalf("secret leaked into SavedLog: %q", saved[0].Message)
	}
	if !strings.Contains(saved[0].Message, "<redacted>") {
		t.Fatalf("expected redacted placeholder, got %q", saved[0].Message)
	}

	svc.ResetLogs()
	if got := len(svc.SavedLog()); got != 0 {
		t.Fatalf("expected 0 entries after ResetLogs, got %d", got)
	}
}
