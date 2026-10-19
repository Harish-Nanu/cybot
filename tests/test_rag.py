from cybot.rag import chunk_markdown, load_directory
from cybot.rag.documents import parse_front_matter
from tests.conftest import KNOWLEDGE_DIR

DOC = """---
title: Test Doc
type: playbook
tags: [a, b]
mitre: [T1110, T1078]
---

Intro paragraph.

## Triage
Check things.

## Containment
Block things.
"""


def test_front_matter_parsing():
    meta, body = parse_front_matter(DOC)
    assert meta["title"] == "Test Doc"
    assert meta["mitre"] == ["T1110", "T1078"]
    assert body.lstrip().startswith("Intro")


def test_chunking_by_section():
    chunks = chunk_markdown(DOC, "playbooks/test.md")
    assert [c.section for c in chunks] == ["Overview", "Triage", "Containment"]
    assert chunks[1].id == "playbooks/test.md#1"
    assert chunks[1].text.startswith("Test Doc\nMITRE ATT&CK: T1110, T1078\nSection: Triage")
    assert chunks[2].metadata()["mitre"] == "T1110,T1078"


def test_load_directory_skips_readme():
    chunks = load_directory(KNOWLEDGE_DIR)
    doc_ids = {c.doc_id for c in chunks}
    assert "README.md" not in doc_ids
    assert "playbooks/brute-force.md" in doc_ids
    assert len(doc_ids) == 19


def test_search_ranks_relevant_playbook(knowledge_base):
    hits = knowledge_base.search("mimikatz lsass credential dumping sekurlsa", k=3)
    assert hits[0].doc_id in {
        "playbooks/credential-dumping.md",
        "mitre/T1003-credential-dumping.md",
    }
    assert all(0 <= h.score <= 1 for h in hits)
    assert hits == sorted(hits, key=lambda h: h.score, reverse=True)

    hits = knowledge_base.search("ssh brute force failed password", k=3)
    assert "playbooks/brute-force.md" in {h.doc_id for h in hits}


def test_search_min_score_and_empty(knowledge_base):
    assert knowledge_base.search("   ") == []
    assert knowledge_base.search("brute force", k=3, min_score=0.99) == []


def test_reindex_is_idempotent(knowledge_base):
    before = knowledge_base.stats()
    knowledge_base.index_directory(KNOWLEDGE_DIR)
    after = knowledge_base.stats()
    assert before == after
    assert after["documents"] == 19
    assert after["embedder"] == "hashing"
