"""Load markdown knowledge documents and split them into retrievable chunks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_FRONT_MATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_SECTION_RE = re.compile(r"^##\s+(.+)$", re.MULTILINE)


@dataclass
class KnowledgeChunk:
    id: str
    doc_id: str
    title: str
    section: str
    text: str
    doc_type: str = "reference"
    tags: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)

    def metadata(self) -> dict[str, str]:
        # Chroma metadata values must be scalars, so lists are stored comma-separated.
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "section": self.section,
            "doc_type": self.doc_type,
            "tags": ",".join(self.tags),
            "mitre": ",".join(self.mitre),
        }


def parse_front_matter(text: str) -> tuple[dict[str, str | list[str]], str]:
    """Minimal YAML-ish front matter parser supporting `key: value` and `key: [a, b]`."""
    match = _FRONT_MATTER_RE.match(text)
    if not match:
        return {}, text
    meta: dict[str, str | list[str]] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if value.startswith("[") and value.endswith("]"):
            meta[key] = [v.strip().strip("'\"") for v in value[1:-1].split(",") if v.strip()]
        else:
            meta[key] = value.strip("'\"")
    return meta, text[match.end() :]


def chunk_markdown(text: str, doc_id: str) -> list[KnowledgeChunk]:
    """Split a document into one chunk per `##` section, prefixed with the document title."""
    meta, body = parse_front_matter(text)
    title = str(meta.get("title") or Path(doc_id).stem.replace("-", " ").title())
    doc_type = str(meta.get("type") or "reference")
    tags = _as_list(meta.get("tags"))
    mitre = _as_list(meta.get("mitre"))

    headings = list(_SECTION_RE.finditer(body))
    sections: list[tuple[str, str]] = []
    intro = body[: headings[0].start()] if headings else body
    if intro.strip():
        sections.append(("Overview", intro.strip()))
    for i, heading in enumerate(headings):
        end = headings[i + 1].start() if i + 1 < len(headings) else len(body)
        content = body[heading.end() : end].strip()
        if content:
            sections.append((heading.group(1).strip(), content))

    header = f"{title}" + (f"\nMITRE ATT&CK: {', '.join(mitre)}" if mitre else "")
    return [
        KnowledgeChunk(
            id=f"{doc_id}#{i}",
            doc_id=doc_id,
            title=title,
            section=section,
            text=f"{header}\nSection: {section}\n\n{content}",
            doc_type=doc_type,
            tags=tags,
            mitre=mitre,
        )
        for i, (section, content) in enumerate(sections)
    ]


def load_directory(directory: Path) -> list[KnowledgeChunk]:
    chunks: list[KnowledgeChunk] = []
    for path in sorted(directory.rglob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        doc_id = path.relative_to(directory).as_posix()
        chunks.extend(chunk_markdown(path.read_text(encoding="utf-8"), doc_id))
    return chunks


def _as_list(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    return value if isinstance(value, list) else [v.strip() for v in value.split(",") if v.strip()]
