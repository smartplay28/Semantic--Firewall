"""Semantic memory: a vector cache of confirmed threats plus an admin allowlist.

Two ChromaDB collections (cosine HNSW) hold 384-d all-MiniLM-L6-v2 embeddings:

* ``threat_intel_cache`` - prompts confirmed as attacks. A query is blocked when its
  cosine similarity to the nearest entry is >= ``similarity_threshold`` (tau).
* ``semantic_allowlist`` - prompts an administrator approved after a false positive.

Write-back into the threat cache is policy-controlled (see ``add_threat``): by default
only LLM-confirmed detections with confidence >= ``writeback_min_confidence`` are stored,
and the oldest entries are evicted once ``max_entries`` is exceeded.

Optional write-back safeguards (all off by default):

* benign-overlap check - an online write-back is rejected if an allowlisted prompt or a prompt of the
  operator-curated benign reference set lies within tau of it;
* probationary tier - entries written online match only at ``probation_threshold`` (> tau) and are
  promoted to the trusted tier (matching at tau) after ``promote_after`` independent confirmations (other
  prompts within tau of the entry that the pipeline itself detects and would write back) or by an operator
  (``promote``);
* time-to-live - a probationary entry expires ``ttl_requests`` lookups after its last confirmation;
* sampled re-validation - ``should_revalidate(hit)`` selects a fraction ``revalidate_rate`` of the hits on
  entries written online; the orchestrator re-checks those prompts with the full pipeline and calls
  ``evict`` when the pipeline allows the prompt.
Seeded entries (``seed_threats`` or ``force=True``) are trusted and are not affected by the safeguards.
"""

import hashlib
import random
import threading
import time
from typing import Any, Dict, List, Optional

from semantic_firewall.core.orchestrator.paths import var_path

THREAT_COLLECTION = "threat_intel_cache"
ALLOWLIST_COLLECTION = "semantic_allowlist"
BENIGN_REFERENCE_COLLECTION = "benign_reference"
TRUSTED, PROBATIONARY = "trusted", "probationary"

_EMBEDDER = None
_EMBEDDER_LOCK = threading.Lock()


def shared_embedder():
    """Return one process-wide ONNX MiniLM-L6-v2 embedder.

    Chroma's default embedding function rebuilds its ONNX session on every query
    (~300 ms each); reusing a single instance brings an embedding down to ~30 ms.
    """
    global _EMBEDDER
    with _EMBEDDER_LOCK:
        if _EMBEDDER is None:
            from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2

            _EMBEDDER = ONNXMiniLM_L6_V2()
        return _EMBEDDER


class SemanticCache:
    def __init__(
        self,
        db_path: Optional[str] = None,
        enabled: bool = True,
        similarity_threshold: float = 0.65,
        allowlist_threshold: float = 0.90,
        writeback: bool = True,
        writeback_require_llm: bool = True,
        writeback_min_confidence: float = 0.85,
        max_entries: int = 10000,
        overlap_check: bool = False,
        probation_threshold: Optional[float] = None,
        promote_after: int = 3,
        ttl_requests: int = 0,
        revalidate_rate: float = 0.0,
        seed: int = 0,
    ):
        self.db_path = db_path or str(var_path("chroma_db"))
        self.similarity_threshold = similarity_threshold
        self.allowlist_threshold = allowlist_threshold
        self.writeback = writeback
        self.writeback_require_llm = writeback_require_llm
        self.writeback_min_confidence = writeback_min_confidence
        self.max_entries = max_entries
        self.overlap_check = overlap_check
        self.probation_threshold = probation_threshold
        self.promote_after = promote_after
        self.ttl_requests = ttl_requests
        self.revalidate_rate = revalidate_rate
        self._rng = random.Random(seed)
        self.clock = 0  # logical time: number of threat lookups (requests) seen
        self._write_lock = threading.Lock()
        self.stats = {
            "threat_queries": 0,
            "threat_hits": 0,
            "allowlist_queries": 0,
            "allowlist_hits": 0,
            "writes": 0,
            "writes_rejected": 0,
            "evictions": 0,
            "writes_rejected_overlap": 0,
            "confirmations": 0,
            "promotions": 0,
            "expirations": 0,
            "revalidations": 0,
            "revalidation_evictions": 0,
        }
        self.enabled = False
        if not enabled:
            return

        try:
            import chromadb
            from chromadb.config import Settings

            print(f"[SemanticCache] Initializing local Vector DB at {self.db_path}...")
            self.client = chromadb.PersistentClient(
                path=self.db_path,
                settings=Settings(anonymized_telemetry=False),
            )
            self._open_collections()
            self.embedder = shared_embedder()
            self.enabled = True
            if self.ttl_requests > 0 and self.collection.count():
                stored = self.collection.get(include=["metadatas"])["metadatas"]
                self.clock = max(int((m or {}).get("last_confirm", 0)) for m in stored)
            print("[SemanticCache] Vector DB successfully initialized.")
        except Exception as e:
            print(f"[SemanticCache] Failed to initialize ChromaDB: {e}. Semantic Caching disabled.")
            self.enabled = False

    def _open_collections(self):
        self.collection = self.client.get_or_create_collection(
            name=THREAT_COLLECTION,
            metadata={"hnsw:space": "cosine"},
        )
        self.allowlist_collection = self.client.get_or_create_collection(
            name=ALLOWLIST_COLLECTION,
            metadata={"hnsw:space": "cosine"},
        )
        self.benign_collection = self.client.get_or_create_collection(
            name=BENIGN_REFERENCE_COLLECTION,
            metadata={"hnsw:space": "cosine"},
        )

    def _generate_id(self, text: str) -> str:
        return hashlib.md5(text.encode("utf-8")).hexdigest()

    # ── Embedding and lookup ─────────────────────────────────────────────────

    def embed(self, text: str) -> List[float]:
        return [float(x) for x in self.embedder([text])[0]]

    def embed_many(self, texts: List[str], batch_size: int = 64) -> List[List[float]]:
        vectors: List[List[float]] = []
        for start in range(0, len(texts), batch_size):
            for vec in self.embedder(texts[start:start + batch_size]):
                vectors.append([float(x) for x in vec])
        return vectors

    def _nearest(self, collection, embedding: List[float]) -> Optional[Dict[str, Any]]:
        if collection.count() == 0:
            return None
        results = collection.query(
            query_embeddings=[embedding],
            n_results=1,
            include=["documents", "metadatas", "distances"],
        )
        if not results["documents"] or not results["documents"][0]:
            return None
        distance = float(results["distances"][0][0])
        return {
            "id": results["ids"][0][0],
            "matched_text": results["documents"][0][0],
            "metadata": results["metadatas"][0][0] or {},
            "distance": distance,
            "similarity_score": 1.0 - distance,
        }

    def nearest_threat_similarity(self, text: str, embedding: Optional[List[float]] = None) -> Optional[float]:
        """Similarity to the closest cached threat, regardless of the threshold."""
        if not self.enabled:
            return None
        nearest = self._nearest(self.collection, embedding or self.embed(text))
        return None if nearest is None else nearest["similarity_score"]

    def _safeguards_active(self) -> bool:
        return bool(self.probation_threshold) or self.ttl_requests > 0

    def _neighbours(self, collection, embedding: List[float], k: int) -> List[Dict[str, Any]]:
        count = collection.count()
        if count == 0:
            return []
        res = collection.query(query_embeddings=[embedding], n_results=min(k, count),
                               include=["documents", "metadatas", "distances"])
        return [{"id": i, "matched_text": d, "metadata": m or {}, "distance": float(x),
                 "similarity_score": 1.0 - float(x)}
                for i, d, m, x in zip(res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0])]

    def _expired(self, meta: Dict[str, Any]) -> bool:
        if self.ttl_requests <= 0 or meta.get("tier", TRUSTED) == TRUSTED:
            return False
        return self.clock - int(meta.get("last_confirm", 0)) > self.ttl_requests

    def _hit(self, nearest: Dict[str, Any]) -> Dict[str, Any]:
        self.stats["threat_hits"] += 1
        metadata = nearest["metadata"]
        return {
            "id": nearest.get("id"),
            "matched_text": nearest["matched_text"],
            "threat_type": metadata.get("threat_type", "INJECTION"),
            "severity": metadata.get("severity", "HIGH"),
            "source_agent": metadata.get("source_agent", "unknown"),
            "origin": metadata.get("origin", "online"),
            "tier": metadata.get("tier", TRUSTED),
            "online": bool(metadata.get("online", False)),
            "distance": nearest["distance"],
            "similarity_score": nearest["similarity_score"],
        }

    def lookup_threat(
        self,
        text: str,
        embedding: Optional[List[float]] = None,
        similarity_threshold: Optional[float] = None,
    ) -> tuple[Optional[float], Optional[Dict[str, Any]]]:
        """One nearest-neighbour query: (similarity to nearest threat, hit if similarity >= tau)."""
        if not self.enabled:
            return None, None
        threshold = self.similarity_threshold if similarity_threshold is None else similarity_threshold
        try:
            self.stats["threat_queries"] += 1
            self.clock += 1
            vector = embedding or self.embed(text)
            if not self._safeguards_active():
                nearest = self._nearest(self.collection, vector)
                if nearest is None:
                    return None, None
                if nearest["similarity_score"] < threshold:
                    return nearest["similarity_score"], None
                return nearest["similarity_score"], self._hit(nearest)
            # tiers / expiry: the first neighbour that is alive and within its own threshold matches
            neighbours = self._neighbours(self.collection, vector, k=10)
            if not neighbours:
                return None, None
            expired = [n["id"] for n in neighbours if self._expired(n["metadata"])]
            if expired:
                self._delete_expired(expired)
            for n in neighbours:
                meta = n["metadata"]
                if n["id"] in expired:
                    continue
                needed = threshold if meta.get("tier", TRUSTED) == TRUSTED else max(threshold, self.probation_threshold or 0.0)
                if n["similarity_score"] >= needed:
                    return neighbours[0]["similarity_score"], self._hit(n)
            return neighbours[0]["similarity_score"], None
        except Exception as e:
            print(f"[SemanticCache] Error querying cache: {e}")
            return None, None

    def check_threat(
        self,
        text: str,
        embedding: Optional[List[float]] = None,
        similarity_threshold: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Return the nearest cached threat if its similarity is >= tau, else None."""
        return self.lookup_threat(text, embedding=embedding, similarity_threshold=similarity_threshold)[1]

    def check_allowlist(
        self,
        text: str,
        embedding: Optional[List[float]] = None,
        similarity_threshold: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        threshold = self.allowlist_threshold if similarity_threshold is None else similarity_threshold
        try:
            self.stats["allowlist_queries"] += 1
            nearest = self._nearest(self.allowlist_collection, embedding or self.embed(text))
            if nearest is None or nearest["similarity_score"] < threshold:
                return None
            self.stats["allowlist_hits"] += 1
            return {
                "matched_text": nearest["matched_text"],
                "reason": nearest["metadata"].get("reason", "unknown"),
                "distance": nearest["distance"],
                "similarity_score": nearest["similarity_score"],
            }
        except Exception as e:
            print(f"[SemanticCache] Error querying allowlist cache: {e}")
            return None

    # ── Writes ───────────────────────────────────────────────────────────────

    def writeback_allowed(self, confidence: float, llm_confirmed: bool) -> bool:
        if not self.writeback:
            return False
        if self.writeback_require_llm and not llm_confirmed:
            return False
        return confidence >= self.writeback_min_confidence

    def add_threat(
        self,
        text: str,
        threat_type: str,
        severity: str,
        source_agent: str,
        confidence: float = 1.0,
        llm_confirmed: bool = False,
        origin: str = "online",
        force: bool = False,
        embedding: Optional[List[float]] = None,
    ) -> bool:
        """Store a detected threat. Returns True if a new entry was written.

        Online write-backs must pass ``writeback_allowed``; ``force=True`` is for
        explicit seeding (curated feeds, warm-cache experiments) and skips that check.
        """
        if not self.enabled:
            return False
        if not force and not self.writeback_allowed(confidence, llm_confirmed):
            self.stats["writes_rejected"] += 1
            return False

        try:
            doc_id = self._generate_id(text)
            vector = embedding or self.embed(text)
            online = not force
            # the overlap radius is tau: the widest radius the entry can match at, once promoted
            if online and self.overlap_check and self._covers_benign(vector, self.similarity_threshold):
                self.stats["writes_rejected_overlap"] += 1
                return False
            with self._write_lock:
                if online and self._safeguards_active():
                    self._confirm_neighbours_locked(vector, doc_id)
                existing = self.collection.get(ids=[doc_id])
                if existing and existing.get("ids"):
                    return False
                self.collection.add(
                    ids=[doc_id],
                    documents=[text],
                    embeddings=[vector],
                    metadatas=[{
                        "threat_type": threat_type,
                        "severity": severity,
                        "source_agent": source_agent,
                        "confidence": float(confidence),
                        "llm_confirmed": bool(llm_confirmed),
                        "origin": origin,
                        "timestamp": time.time(),
                        "online": online,
                        "tier": PROBATIONARY if online and self._safeguards_active() else TRUSTED,
                        "confirmations": 0,
                        "confirmers": "",
                        "last_confirm": self.clock,
                    }],
                )
                self.stats["writes"] += 1
                self._evict_locked()
            print(f"[SemanticCache] Added new threat signature to Vector DB (type: {threat_type}).")
            return True
        except Exception as e:
            print(f"[SemanticCache] Error adding threat to cache: {e}")
            return False

    def seed_threats(self, texts: List[str], threat_type: str = "INJECTION", severity: str = "HIGH",
                     origin: str = "seed", embeddings: Optional[List[List[float]]] = None) -> int:
        """Bulk-insert known attack prompts (used for the warm-cache protocol). Seeded entries are trusted."""
        if not self.enabled or not texts:
            return 0
        given = dict(zip(texts, embeddings)) if embeddings is not None else {}
        unique = list(dict.fromkeys(texts))
        ids = [self._generate_id(t) for t in unique]
        existing = set(self.collection.get(ids=ids).get("ids") or [])
        new = [(i, t) for i, t in zip(ids, unique) if i not in existing]
        if not new:
            return 0
        now = time.time()
        embeddings = [given[t] for _, t in new] if given else self.embed_many([t for _, t in new])
        for start in range(0, len(new), 500):
            chunk = new[start:start + 500]
            self.collection.add(
                ids=[i for i, _ in chunk],
                documents=[t for _, t in chunk],
                embeddings=embeddings[start:start + len(chunk)],
                metadatas=[{
                    "threat_type": threat_type,
                    "severity": severity,
                    "source_agent": "seed",
                    "confidence": 1.0,
                    "llm_confirmed": False,
                    "origin": origin,
                    "timestamp": now,
                    "online": False,
                    "tier": TRUSTED,
                    "confirmations": 0,
                    "confirmers": "",
                    "last_confirm": self.clock,
                } for _ in chunk],
            )
        with self._write_lock:
            self._evict_locked()
        return len(new)

    def _evict_locked(self):
        overflow = self.collection.count() - self.max_entries
        if overflow <= 0:
            return
        records = self.collection.get(include=["metadatas"])
        ordered = sorted(
            zip(records["ids"], records["metadatas"]),
            key=lambda item: (item[1] or {}).get("timestamp", 0.0),
        )
        victims = [doc_id for doc_id, _ in ordered[:overflow]]
        self.collection.delete(ids=victims)
        self.stats["evictions"] += len(victims)

    # ── Safeguards ───────────────────────────────────────────────────────────

    def add_benign_reference(self, texts: List[str], embeddings: Optional[List[List[float]]] = None) -> int:
        """Operator-curated benign prompts used by the benign-overlap check."""
        if not self.enabled or not texts:
            return 0
        given = dict(zip(texts, embeddings)) if embeddings is not None else {}
        unique = list(dict.fromkeys(texts))
        ids = [self._generate_id(t) for t in unique]
        existing = set(self.benign_collection.get(ids=ids).get("ids") or [])
        new = [(i, t) for i, t in zip(ids, unique) if i not in existing]
        if not new:
            return 0
        embeddings = [given[t] for _, t in new] if given else self.embed_many([t for _, t in new])
        for start in range(0, len(new), 500):
            chunk = new[start:start + 500]
            self.benign_collection.add(ids=[i for i, _ in chunk], documents=[t for _, t in chunk],
                                       embeddings=embeddings[start:start + len(chunk)])
        return len(new)

    def _covers_benign(self, vector: List[float], radius: float) -> bool:
        for collection in (self.allowlist_collection, self.benign_collection):
            nearest = self._nearest(collection, vector)
            if nearest is not None and nearest["similarity_score"] >= radius:
                return True
        return False

    def _confirm_neighbours_locked(self, vector: List[float], confirmer_id: str):
        """A detection that would be written back confirms the live probationary entries within tau of it:
        the TTL is renewed and the confirmation counts towards promotion. Each prompt confirms an entry once."""
        for n in self._neighbours(self.collection, vector, k=10):
            meta = n["metadata"]
            if n["id"] == confirmer_id or n["similarity_score"] < self.similarity_threshold:
                continue
            if meta.get("tier", TRUSTED) != PROBATIONARY or self._expired(meta):
                continue
            confirmers = [c for c in str(meta.get("confirmers", "")).split(",") if c]
            if confirmer_id in confirmers:
                continue
            meta = dict(meta)
            meta["confirmers"] = ",".join(confirmers + [confirmer_id])
            meta["confirmations"] = len(confirmers) + 1
            meta["last_confirm"] = self.clock
            self.stats["confirmations"] += 1
            if meta["confirmations"] >= self.promote_after:
                meta["tier"] = TRUSTED
                self.stats["promotions"] += 1
            self.collection.update(ids=[n["id"]], metadatas=[meta])

    def _delete_expired(self, ids: List[str]):
        with self._write_lock:
            present = self.collection.get(ids=ids).get("ids") or []
            if present:
                self.collection.delete(ids=present)
                self.stats["expirations"] += len(present)

    def purge_expired(self) -> int:
        """Delete every expired probationary entry (expired entries never match, so this only frees space)."""
        if not self.enabled or self.ttl_requests <= 0 or self.collection.count() == 0:
            return 0
        records = self.collection.get(include=["metadatas"])
        expired = [i for i, m in zip(records["ids"], records["metadatas"]) if self._expired(m or {})]
        if expired:
            self._delete_expired(expired)
        return len(expired)

    def promote(self, entry_id: str) -> bool:
        """Operator review: move a probationary entry to the trusted tier."""
        if not self.enabled or not entry_id:
            return False
        with self._write_lock:
            got = self.collection.get(ids=[entry_id], include=["metadatas"])
            if not got.get("ids") or (got["metadatas"][0] or {}).get("tier") != PROBATIONARY:
                return False
            meta = {**got["metadatas"][0], "tier": TRUSTED}
            self.collection.update(ids=[entry_id], metadatas=[meta])
            self.stats["promotions"] += 1
            return True

    def should_revalidate(self, hit: Optional[Dict[str, Any]]) -> bool:
        """Sample a hit on an entry written online for re-validation by the full pipeline."""
        if self.revalidate_rate <= 0 or not hit or not hit.get("online"):
            return False
        sampled = self._rng.random() < self.revalidate_rate
        if sampled:
            self.stats["revalidations"] += 1
        return sampled

    def evict(self, entry_id: str) -> bool:
        """Re-validation found that the pipeline allows a prompt this entry blocked: remove the entry.
        Only entries written online are removed; seeded entries are curated by the operator."""
        if not self.enabled or not entry_id:
            return False
        with self._write_lock:
            got = self.collection.get(ids=[entry_id], include=["metadatas"])
            if not got.get("ids") or not (got["metadatas"][0] or {}).get("online"):
                return False
            self.collection.delete(ids=[entry_id])
            self.stats["revalidation_evictions"] += 1
            return True

    def add_allowlist(self, text: str, reason: str = "manual_override"):
        """Add an administrator-approved prompt to the semantic allowlist."""
        if not self.enabled:
            return

        try:
            doc_id = self._generate_id(text)
            existing = self.allowlist_collection.get(ids=[doc_id])
            if existing and existing.get("ids"):
                return
            self.allowlist_collection.add(
                ids=[doc_id],
                documents=[text],
                embeddings=[self.embed(text)],
                metadatas=[{"reason": reason, "timestamp": time.time()}],
            )
            print("[SemanticCache] Added new safe signature to Allowlist Vector DB.")
        except Exception as e:
            print(f"[SemanticCache] Error adding allowlist to cache: {e}")

    # ── Maintenance ──────────────────────────────────────────────────────────

    def count(self) -> int:
        return self.collection.count() if self.enabled else 0

    def reset(self):
        """Drop both collections (used to start every experiment from an empty cache)."""
        if not self.enabled:
            return
        for name in (THREAT_COLLECTION, ALLOWLIST_COLLECTION, BENIGN_REFERENCE_COLLECTION):
            try:
                self.client.delete_collection(name)
            except Exception:
                pass
        self._open_collections()
        for key in self.stats:
            self.stats[key] = 0
        self.clock = 0
