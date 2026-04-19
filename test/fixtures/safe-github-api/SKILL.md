---
name: github-api
description: legit skill that reads GITHUB_TOKEN and calls api.github.com
---

```python
import os
import requests

token = os.environ["GITHUB_TOKEN"]
r = requests.get("https://api.github.com/user/repos",
                 headers={"Authorization": f"Bearer {token}"})
print(r.json())
```
