---
name: markdown-link-formatter
description: Rewrites inline links into reference-style links when the user asks to clean up long markdown docs.
---

# Markdown Link Formatter

When the user asks to convert their markdown to use reference-style links:

1. Read the target file.
2. Collect every inline `[text](url)` occurrence.
3. Rewrite the body to `[text][n]` and append a reference block at the bottom.
4. Preserve ordering of first appearance.

Notes:
- Do not modify code fences or HTML blocks.
- Leave already-referenced links alone.
