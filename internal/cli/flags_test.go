package cli

import (
	"strings"
	"testing"

	"github.com/thexsa/peep/internal/education"
)

func TestRemovedFlagAliasesAndRetainedBaseFlags(t *testing.T) {
	pflags := rootCmd.PersistentFlags()

	// Removed aliases MUST NOT be registered
	for _, removed := range []string{"lens", "gaze", "knock"} {
		if f := pflags.Lookup(removed); f != nil {
			t.Errorf("flag alias --%s should have been removed, but is still registered", removed)
		}
	}

	// Base flags MUST still be registered with their short flags intact
	expectedBase := []struct {
		long  string
		short string
	}{
		{long: "proto", short: "P"},
		{long: "details", short: "d"},
		{long: "connect", short: "c"},
	}

	for _, exp := range expectedBase {
		f := pflags.Lookup(exp.long)
		if f == nil {
			t.Fatalf("base flag --%s is missing", exp.long)
		}
		if f.Shorthand != exp.short {
			t.Errorf("base flag --%s shorthand = %q, want %q", exp.long, f.Shorthand, exp.short)
		}
		for _, removed := range []string{"--lens", "--gaze", "--knock"} {
			if strings.Contains(f.Usage, removed) {
				t.Errorf("base flag --%s usage %q still mentions removed alias %s", exp.long, f.Usage, removed)
			}
		}
	}

	// Built-in docs should not mention removed aliases either
	for _, topic := range education.GetTopics() {
		for _, removed := range []string{"--lens", "--gaze", "--knock"} {
			if strings.Contains(topic.Content, removed) {
				t.Errorf("doc topic %q still mentions removed alias %s", topic.Name, removed)
			}
		}
	}
}
