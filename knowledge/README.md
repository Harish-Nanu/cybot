# Knowledge base

Markdown documents indexed into the vector store for retrieval-augmented analysis.
Each file starts with a YAML-style front matter block:

```
---
title: Human readable title
type: playbook | technique | policy | asset
tags: [comma, separated]
mitre: [T1110, T1078]
---
```

Documents are chunked by `##` headings. Add or edit files here, then re-index with
`cybot index` or `POST /api/v1/knowledge/reindex`.
