---
name: docstring-zip
description: Python script with docstring mentioning zip + pretty-prints — must NOT fire R05 PASSWORD_ZIP
---

```python
"""
Unpacks a ZIP archive, pretty-prints XML files using xmllint, and returns them.
"""
import zipfile
def unpack(path):
    with zipfile.ZipFile(path) as z:
        z.extractall()
```
