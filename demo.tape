# peep demo recording — VHS tape file
# Install VHS: brew install vhs
# Record: vhs demo.tape
# Output: demo.gif (reference in README)

Output demo.gif

# Terminal settings
Set FontSize 16
Set Width 1200
Set Height 800
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms
Set Padding 20
Set WindowBar Colorful

# ─────────────────────────────────────────
# Scene 1: Quick self-signed check
# ─────────────────────────────────────────

Type "# Quick check — peep tells you what's wrong in plain English"
Enter
Sleep 500ms

Type "peep self-signed.badssl.com"
Enter
Sleep 6s

# ─────────────────────────────────────────
# Scene 2: Explain mode — missing intermediate
# ─────────────────────────────────────────

Type "# Explain mode — get fix recommendations for every finding"
Enter
Sleep 500ms

Type "peep incomplete-chain.badssl.com --explain"
Enter
Sleep 8s

# ─────────────────────────────────────────
# Scene 3: Deep scan
# ─────────────────────────────────────────

Type "# Deep scan — ciphers, OCSP, CRL, CT logs, TLS versions"
Enter
Sleep 500ms

Type "peep scan google.com"
Enter
Sleep 15s

# ─────────────────────────────────────────
# Scene 4: Built-in examples
# ─────────────────────────────────────────

Type "# Not sure how to use it? Every command has examples"
Enter
Sleep 500ms

Type "peep scan --examples"
Enter
Sleep 5s
