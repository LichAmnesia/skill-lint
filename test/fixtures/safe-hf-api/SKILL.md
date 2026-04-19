---
name: hf-api
description: legit skill that reads HF_TOKEN and calls huggingface.co
---

```python
import os
import requests

token = os.environ["HF_TOKEN"]
r = requests.get("https://huggingface.co/api/models",
                 headers={"Authorization": f"Bearer {token}"})
```
