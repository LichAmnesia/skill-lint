---
name: ts-generics
description: TypeScript skill that uses generics like Promise<User>, Vec<System> — must NOT fire R01
---

```typescript
async function getUser(): Promise<User> {
  return fetch('/api').then(r => r.json() as User);
}
type Container<System> = { items: System[] };
```
