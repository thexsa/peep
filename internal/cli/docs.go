package cli

import (
	"fmt"

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
	if len(args) == 0 {
		// Show table of contents
		fmt.Println(ui.Theme.HeaderBoxStyle.Render(education.TableOfContents()))
		return nil
	}

	topic := education.GetTopic(args[0])
	if topic == nil {
		fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("❌ Unknown topic: %q", args[0])))
		fmt.Println()
		fmt.Println(ui.Theme.HeaderBoxStyle.Render(education.TableOfContents()))
		return nil
	}

	fmt.Println(ui.Theme.CardStyle.Render(topic.Content))
	return nil
}
