"""Local RAG / Vector Store for MITRE ATT&CK v19.2.

Provides lightweight, in-memory semantic retrieval across 697 ATT&CK techniques
using subword n-gram TF-IDF vectorization and cosine similarity. Runs 100% locally
without external cloud dependencies or API keys.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger("threatfusion.vector_store")

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TECHNIQUES_PATH = ROOT / "src" / "reference" / "techniques.json"


class AttackVectorStore:
    """Local vector store for MITRE ATT&CK technique descriptions."""

    def __init__(self, techniques_path: Path | str | None = None) -> None:
        self.techniques_path = Path(techniques_path) if techniques_path else DEFAULT_TECHNIQUES_PATH
        self.techniques: list[dict[str, Any]] = []
        self.technique_by_id: dict[str, dict[str, Any]] = {}
        self.vectorizer: TfidfVectorizer | None = None
        self.matrix: Any = None
        self._corpus: list[str] = []
        self._initialize()

    def _initialize(self) -> None:
        """Load techniques and build the vector index."""
        if not self.techniques_path.exists():
            logger.warning("Techniques file not found at %s", self.techniques_path)
            return

        with open(self.techniques_path, encoding="utf-8") as f:
            self.techniques = json.load(f)

        self.technique_by_id = {t["id"]: t for t in self.techniques}

        # Build rich corpus text incorporating ID, name, tactics, platforms, and full description
        self._corpus = []
        for t in self.techniques:
            tactics = " ".join(t.get("tactics", []))
            platforms = " ".join(t.get("platforms", []))
            desc = t.get("description", "")
            text = f"{t['id']} {t.get('name', '')} {tactics} {platforms} {desc}"
            self._corpus.append(text)

        # Sublinear TF with 1-2 ngrams provides great balance between exact terms and semantic context
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words="english",
            sublinear_tf=True,
            max_features=15000,
        )
        self.matrix = self.vectorizer.fit_transform(self._corpus)
        logger.info("AttackVectorStore indexed %d techniques", len(self.techniques))

    def search(
        self,
        query: str,
        top_k: int = 5,
        tactic_filter: str | None = None,
        min_score: float = 0.05,
    ) -> list[dict[str, Any]]:
        """Search for top matching ATT&CK techniques given alert telemetry text."""
        if not query or not query.strip() or self.vectorizer is None or self.matrix is None:
            return []

        cleaned_query = query.strip().lower()
        query_vec = self.vectorizer.transform([cleaned_query])
        sims = cosine_similarity(query_vec, self.matrix)[0]

        # Get sorted candidate indices
        sorted_indices = np.argsort(-sims)
        results: list[dict[str, Any]] = []

        for idx in sorted_indices:
            score = float(sims[idx])
            if score < min_score:
                break

            tech = self.techniques[idx]
            tactics = tech.get("tactics", [])

            if tactic_filter and tactic_filter.lower() not in [t.lower() for t in tactics]:
                continue

            desc = tech.get("description", "")
            snippet = desc[:200] + "..." if len(desc) > 200 else desc

            results.append({
                "technique_id": tech["id"],
                "name": tech.get("name", tech["id"]),
                "tactics": tactics,
                "score": round(score, 3),
                "is_subtechnique": tech.get("is_subtechnique", False),
                "description_snippet": snippet,
                "explanation": f"Semantic similarity match ({round(score * 100, 1)}%) based on ATT&CK description.",
            })

            if len(results) >= top_k:
                break

        return results

    def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        """Retrieve technique details by ATT&CK ID."""
        return self.technique_by_id.get(technique_id)

    def count(self) -> int:
        """Return total indexed techniques."""
        return len(self.techniques)


# Global singleton instance for high-performance reuse
_global_store: AttackVectorStore | None = None


def get_vector_store() -> AttackVectorStore:
    """Return or initialize global AttackVectorStore singleton."""
    global _global_store
    if _global_store is None:
        _global_store = AttackVectorStore()
    return _global_store
