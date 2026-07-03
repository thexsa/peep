package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/analyzer"
	"github.com/thexsa/peep/internal/education"
	"github.com/thexsa/peep/internal/ui"
)

var (
	flagDocsSearch string
	flagDocsAll    bool
)

var docsCmd = &cobra.Command{
	Use:   "docs [topic]",
	Short: "📚 Built-in TLS reference guide (supports --search, --all, --json)",
	Long: `Access peep's built-in educational documentation.
Learn about TLS, certificates, cipher suites, and more —
written for humans, not RFCs.

Available topics:
  tls              What is TLS? Version history
  tls-handshake    TLS 1.2 vs 1.3 handshake flows
  certs            Leaf vs Intermediate vs Root
  chain            How chain of trust works
  ciphers          Cipher suites explained
  crl              Certificate Revocation Lists
  ocsp             Online Certificate Status Protocol
  aia              Authority Information Access
  starttls         What STARTTLS is
  rdp              Why RDP certs are special
  troubleshooting  Common issues & what to check

Flags:
      --search <term>      Search all topics for a keyword
      --all             Display all topics at once (man-page style)
  -j, --json            Output results as JSON

Examples:
  peep docs tls
  peep docs --search java
  peep docs --search "cipher suite" --json
  peep docs --all
  peep docs --all --json

Run 'peep docs' with no topic to see the full table of contents.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDocs,
}

func init() {
	docsCmd.Flags().StringVar(&flagDocsSearch, "search", "", "Search all topics for a keyword")
	docsCmd.Flags().BoolVar(&flagDocsAll, "all", false, "Display all topics at once (man-page style)")
	rootCmd.AddCommand(docsCmd)
}

// jsonTopic is the JSON representation of a doc topic.
type jsonTopic struct {
	Name    string   `json:"name"`
	Title   string   `json:"title"`
	Summary string   `json:"summary"`
	Content []string `json:"content"`
}

// toJSONTopic converts an education.Topic into a clean jsonTopic
// with content split into lines and stripped of terminal formatting.
func toJSONTopic(t *education.Topic) jsonTopic {
	return jsonTopic{
		Name:    t.Name,
		Title:   t.Title,
		Summary: t.Summary,
		Content: cleanForJSON(t.Content),
	}
}

// blankLineRe matches 3+ consecutive blank lines.
var blankLineRe = regexp.MustCompile(`\n{4,}`)

// cleanForJSON strips emoji, box-drawing characters, and excessive
// whitespace from doc content for clean JSON output.
func cleanForJSON(s string) []string {
	// Step 1: Semantic replacements — convert meaningful symbols to ASCII
	semantic := strings.NewReplacer(
		"✅", "[PASS]", "❌", "[FAIL]",
		"⚠️", "[!]", "⚠", "[!]",
		"→", "->", "←", "<-",
		"—", "--", "–", "-",
		"━", "-", "─", "-", "═", "=",
		"│", "|", "┃", "|",
		"┌", "+", "┐", "+", "└", "+", "┘", "+",
		"├", "+", "┤", "+",
		"•", "*",
	)
	s = semantic.Replace(s)

	// Step 2: Strip all remaining non-ASCII characters (emoji, decorative unicode, etc.)
	// Keep only printable ASCII (0x20-0x7E), tabs, and newlines.
	var cleaned strings.Builder
	cleaned.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\t' || (r >= 0x20 && r <= 0x7E) {
			cleaned.WriteRune(r)
		}
		// else: drop the character (emoji, box-drawing, decorative unicode)
	}
	s = cleaned.String()

	// Collapse 3+ consecutive newlines into 2 (one blank line)
	s = blankLineRe.ReplaceAllString(s, "\n\n")

	// Split into lines, trim each line's trailing whitespace,
	// and drop leading/trailing empty lines
	raw := strings.Split(s, "\n")
	var lines []string
	for _, line := range raw {
		lines = append(lines, strings.TrimRight(line, " \t"))
	}

	// Trim leading empty lines
	for len(lines) > 0 && lines[0] == "" {
		lines = lines[1:]
	}
	// Trim trailing empty lines
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	return lines
}

// sanitizeForJSON cleans a plain string for JSON output by replacing
// non-ASCII characters with ASCII equivalents. Unlike cleanForJSON,
// this does NOT split into lines — it's for warning fields, titles, etc.
func sanitizeForJSON(s string) string {
	// Semantic replacements for meaningful characters
	s = strings.NewReplacer(
		"→", "->", "←", "<-",
		"—", "--", "–", "-",
		"≥", ">=", "≤", "<=",
		"•", "*",
	).Replace(s)

	// Strip any remaining non-ASCII characters
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\t' || (r >= 0x20 && r <= 0x7E) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeWarnings cleans all string fields in a Warning slice for JSON output.
func sanitizeWarnings(warnings []analyzer.Warning) []analyzer.Warning {
	cleaned := make([]analyzer.Warning, len(warnings))
	for i, w := range warnings {
		cleaned[i] = analyzer.Warning{
			Code:     w.Code,
			Severity: w.Severity,
			Title:    sanitizeForJSON(w.Title),
			Detail:   sanitizeForJSON(w.Detail),
			Explain:  sanitizeForJSON(w.Explain),
			Fix:      sanitizeForJSON(w.Fix),
			DocRef:   sanitizeForJSON(w.DocRef),
		}
	}
	return cleaned
}

// marshalCleanJSON marshals v to indented JSON, then recursively sanitizes
// all string values to replace non-ASCII characters with ASCII equivalents.
// This is the single point of sanitization for all JSON output.
func marshalCleanJSON(v interface{}) ([]byte, error) {
	// Marshal to JSON first
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}

	// Unmarshal into generic interface for recursive sanitization
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}

	// Recursively sanitize all string values
	sanitized := sanitizeJSONValue(generic)

	// Re-marshal the sanitized data
	return json.MarshalIndent(sanitized, "", "  ")
}

// sanitizeJSONValue recursively walks a JSON-decoded value and applies
// sanitizeForJSON to all string values.
func sanitizeJSONValue(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return sanitizeForJSON(val)
	case map[string]interface{}:
		for k, child := range val {
			val[k] = sanitizeJSONValue(child)
		}
		return val
	case []interface{}:
		for i, child := range val {
			val[i] = sanitizeJSONValue(child)
		}
		return val
	default:
		return v
	}
}

// jsonSearchMatch represents a search result with matching context lines.
type jsonSearchMatch struct {
	Topic   string   `json:"topic"`
	Title   string   `json:"title"`
	Matches []string `json:"matches"` // matching lines
}

func runDocs(cmd *cobra.Command, args []string) error {
	if flagPlainText {
		ui.EnablePlainText()
	}

	// --search mode
	if flagDocsSearch != "" {
		return runDocsSearch(flagDocsSearch)
	}

	// --all mode
	if flagDocsAll {
		return runDocsAll()
	}

	// No args: show table of contents
	if len(args) == 0 {
		if flagJSON {
			return renderDocsListJSON()
		}
		toc := ui.StripEmoji(education.TableOfContents())
		fmt.Println(ui.Theme.HeaderBoxStyle.Render(toc))
		return nil
	}

	// Single topic
	topic := education.GetTopic(args[0])
	if topic == nil {
		msg := ui.StripEmoji(fmt.Sprintf("❌ Unknown topic: %q", args[0]))
		fmt.Println(ui.Theme.ErrorStyle.Render(msg))
		fmt.Println()
		toc := ui.StripEmoji(education.TableOfContents())
		fmt.Println(ui.Theme.HeaderBoxStyle.Render(toc))
		return nil
	}

	if flagJSON {
		return renderTopicJSON(topic)
	}

	// Render content line-by-line with manual border (no lipgloss right-padding)
	contentLines := strings.Split(topic.Content, "\n")
	fmt.Println(ui.ApplyBorder(contentLines, ui.CardBorder))
	return nil
}

// runDocsSearch searches all topics for a keyword and displays results.
func runDocsSearch(query string) error {
	queryLower := strings.ToLower(query)
	topics := education.GetTopics()

	type searchHit struct {
		topic   *education.Topic
		matches []string // contextual matching lines
	}

	var hits []searchHit

	for i := range topics {
		t := &topics[i]
		contentLower := strings.ToLower(t.Content)
		titleLower := strings.ToLower(t.Title)
		summaryLower := strings.ToLower(t.Summary)

		if !strings.Contains(contentLower, queryLower) &&
			!strings.Contains(titleLower, queryLower) &&
			!strings.Contains(summaryLower, queryLower) {
			continue
		}

		// Extract matching lines for context
		var matchLines []string
		for _, line := range strings.Split(t.Content, "\n") {
			if strings.Contains(strings.ToLower(line), queryLower) {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" && len(matchLines) < 3 { // max 3 context lines per topic
					matchLines = append(matchLines, trimmed)
				}
			}
		}
		hits = append(hits, searchHit{topic: t, matches: matchLines})
	}

	if len(hits) == 0 {
		if flagJSON {
			fmt.Println("[]")
			return nil
		}
		fmt.Println(ui.Theme.WarningStyle.Render(
			fmt.Sprintf("  No topics found matching %q", query)))
		fmt.Println()
		toc := ui.StripEmoji(education.TableOfContents())
		fmt.Println(ui.Theme.HeaderBoxStyle.Render(toc))
		return nil
	}

	// JSON mode: output full content of matching topics
	if flagJSON {
		var results []jsonTopic
		for _, h := range hits {
			results = append(results, toJSONTopic(h.topic))
		}
		data, err := marshalCleanJSON(results)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// If exactly one match, display the full topic
	if len(hits) == 1 {
		contentLines := strings.Split(hits[0].topic.Content, "\n")
		fmt.Println(ui.ApplyBorder(contentLines, ui.CardBorder))
		return nil
	}

	// Multiple matches: show summary
	fmt.Println(ui.Theme.InfoStyle.Render(
		fmt.Sprintf("  Found %q in %d topics:\n", query, len(hits))))

	for _, h := range hits {
		fmt.Printf("    %-20s", h.topic.Name)
		if len(h.matches) > 0 {
			// Show first match line as context
			context := h.matches[0]
			if len(context) > 80 {
				context = context[:77] + "..."
			}
			fmt.Printf(" — %s", ui.Theme.MutedStyle.Render(context))
		}
		fmt.Println()
	}

	fmt.Println()
	fmt.Println(ui.Theme.MutedStyle.Render("  Run: peep docs <topic> to read the full topic."))
	return nil
}

// runDocsAll outputs all documentation topics at once.
func runDocsAll() error {
	topics := education.GetTopics()

	if flagJSON {
		var results []jsonTopic
		for _, t := range topics {
			results = append(results, toJSONTopic(&t))
		}
		data, err := marshalCleanJSON(results)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Man-page style: render all topics sequentially
	for i, t := range topics {
		contentLines := strings.Split(t.Content, "\n")
		fmt.Println(ui.ApplyBorder(contentLines, ui.CardBorder))
		if i < len(topics)-1 {
			fmt.Println() // separator between topics
		}
	}
	return nil
}

// renderDocsListJSON outputs the table of contents as JSON.
func renderDocsListJSON() error {
	topics := education.GetTopics()
	type tocEntry struct {
		Name    string `json:"name"`
		Title   string `json:"title"`
		Summary string `json:"summary"`
	}
	var entries []tocEntry
	for _, t := range topics {
		entries = append(entries, tocEntry{
			Name:    t.Name,
			Title:   t.Title,
			Summary: t.Summary,
		})
	}
	data, err := marshalCleanJSON(entries)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// renderTopicJSON outputs a single topic as JSON.
func renderTopicJSON(topic *education.Topic) error {
	out := toJSONTopic(topic)
	data, err := marshalCleanJSON(out)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}
