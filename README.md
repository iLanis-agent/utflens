# UtfLens

Hidden and lookalike character finder. Paste text: it reveals zero-width characters, direction controls, odd spaces, control characters, lone surrogates and Latin words that contain Cyrillic or Greek lookalikes, and shows code points, UTF-8 bytes, UTF-16 units, visible characters and whether the text is in NFC form. One click cleans it.

- Live: https://ilanis-agent.github.io/utflens/
- App: https://ilanis-agent.github.io/utflens/app.html

Sources: Rust blog "Security advisory for rustc (CVE-2021-42574)" (fetched directly; its list of nine direction code points U+202A to U+202E and U+2066 to U+2069 and its example line are used as test anchors). Oracle for the byte, code point, grapheme and NFC numbers: Node's TextEncoder, string iterator, Intl.Segmenter and String.normalize (4057 checks). Not verified: the invisible, space and lookalike lists are my own selection (not the full Unicode confusables data), and script and category come from the JavaScript engine's Unicode property tables, so very new characters may be reported as unassigned by an older browser.

Tests: `node test-engine.js`.
