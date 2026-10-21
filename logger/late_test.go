package logger

import (
	"bytes"
	"strings"
	"testing"

	corelogger "github.com/go-gost/core/logger"
)

func newBufLogger(t *testing.T, buf *bytes.Buffer) corelogger.Logger {
	t.Helper()
	return NewLogger(
		OutputOption(buf),
		FormatOption(corelogger.TextFormat),
		LevelOption(corelogger.InfoLevel),
	)
}

// A late logger must follow whichever logger is the global default at the time
// a message is logged: components are built during config loading, but the host
// application installs its own logger afterwards.
func TestLateLoggerFollowsCurrentDefault(t *testing.T) {
	var first, second bytes.Buffer
	corelogger.SetDefault(newBufLogger(t, &first))
	t.Cleanup(func() { corelogger.SetDefault(newBufLogger(t, &bytes.Buffer{})) })

	l := LateLogger().WithFields(map[string]any{"node": "wg-node"})
	l.Infof("before")

	if !strings.Contains(first.String(), "before") {
		t.Fatalf("first logger did not receive the message: %q", first.String())
	}
	if !strings.Contains(first.String(), "wg-node") {
		t.Fatalf("fields are missing from the message: %q", first.String())
	}

	// The host application replaces the default logger (e.g. after loader.Load).
	corelogger.SetDefault(newBufLogger(t, &second))
	l.Infof("after")

	if !strings.Contains(second.String(), "after") {
		t.Fatalf("late logger did not follow the new default: %q", second.String())
	}
	if !strings.Contains(second.String(), "wg-node") {
		t.Fatalf("fields were lost after the switch: %q", second.String())
	}
	if strings.Contains(first.String(), "after") {
		t.Fatalf("late logger kept writing to the old default: %q", first.String())
	}
}

func TestLateLoggerWithFieldsMerges(t *testing.T) {
	var buf bytes.Buffer
	corelogger.SetDefault(newBufLogger(t, &buf))
	t.Cleanup(func() { corelogger.SetDefault(newBufLogger(t, &bytes.Buffer{})) })

	LateLogger().
		WithFields(map[string]any{"node": "n1"}).
		WithFields(map[string]any{"dialer": "wg"}).
		Infof("merged")

	got := buf.String()
	for _, want := range []string{"node", "n1", "dialer", "wg", "merged"} {
		if !strings.Contains(got, want) {
			t.Fatalf("message %q is missing %q", got, want)
		}
	}
}

func TestLateLoggerFallsBackToNop(t *testing.T) {
	// A nil default cannot be installed (SetDefault(nil) panics inside
	// sync/atomic), so this only pins that Level queries stay usable.
	l := LateLogger()
	_ = l.GetLevel()
	_ = l.IsLevelEnabled(corelogger.InfoLevel)
	l.Infof("no panic")
}
