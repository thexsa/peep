package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/education"
	"github.com/thexsa/peep/internal/ui"
)

var docsCmd = &cobra.Command{
	Use:   "docs [topic]",
	Short: "📚 Built-in TLS reference guide",
	Long: `Access peep's built-in educational documentation.
Learn about TLS, certificates, cipher suites, and more —
written for humans, not RFCs.

Available topics:
  tls              What is TLS? Version history
  certs            Leaf vs Intermediate vs Root
  chain            How chain of trust works
  ciphers          Cipher suites explained
  starttls         What STARTTLS is
  rdp              Why RDP certs are special
  troubleshooting  Common issues & what to check

Run 'peep docs' with no topic to see the full table of contents.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDocs,
}

func init() {
	rootCmd.AddCommand(docsCmd)
}

func runDocs(cmd *cobra.Command, args []string) error {
	if flagPlainText {
		ui.EnablePlainText()
	}

	if len(args) == 0 {
		// Show table of contents
		toc := ui.StripEmoji(education.TableOfContents())
		fmt.Println(ui.Theme.HeaderBoxStyle.Render(toc))
		return nil
	}

	topic := education.GetTopic(args[0])
	if topic == nil {
		msg := ui.StripEmoji(fmt.Sprintf("❌ Unknown topic: %q", args[0]))
		fmt.Println(ui.Theme.ErrorStyle.Render(msg))
		fmt.Println()
		toc := ui.StripEmoji(education.TableOfContents())
		fmt.Println(ui.Theme.HeaderBoxStyle.Render(toc))
		return nil
	}

	// Render content line-by-line with manual border (no lipgloss right-padding)
	contentLines := strings.Split(topic.Content, "\n")
	fmt.Println(ui.ApplyBorder(contentLines, ui.CardBorder))
	return nil
}
