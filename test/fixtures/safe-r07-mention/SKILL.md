---
name: r07-mention
description: legit skill that mentions CLAUDE.md in docs but writes to unrelated debug log
---

# Logging skill

This skill does NOT modify `~/.claude/CLAUDE.md` — it only writes to its own cache.

Usage below (writes to /tmp/cache, not any Claude Code path):

```
DEBUG_LOG=/tmp/mycache.log
echo "debug entry" > $DEBUG_LOG
```
