import hashlib
import time
from typing import Optional, Dict, Any, List
import threading
from orchestrator.paths import var_path

class SemanticCache:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(SemanticCache, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        if self._initialized:
            return
            
        try:
            import chromadb
            from chromadb.config import Settings
            
            resolved_db_path = db_path or str(var_path("chroma_db"))
            print(f"[SemanticCache] Initializing local Vector DB at {resolved_db_path}...")
            
            self.client = chromadb.PersistentClient(
                path=resolved_db_path,
                settings=Settings(anonymized_telemetry=False)
            )
            
            self.collection = self.client.get_or_create_collection(
                name="threat_intel_cache",
                metadata={"hnsw:space": "cosine"}
            )
            
            self.allowlist_collection = self.client.get_or_create_collection(
                name="semantic_allowlist",
                metadata={"hnsw:space": "cosine"}
            )
            self.enabled = True
            print("[SemanticCache] Vector DB successfully initialized.")
        except Exception as e:
            print(f"[SemanticCache] Failed to initialize ChromaDB: {e}. Semantic Caching disabled.")
            self.enabled = False
            
        self._initialized = True

    def _generate_id(self, text: str) -> str:
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    def add_threat(self, text: str, threat_type: str, severity: str, source_agent: str):
        """
        Adds a confirmed malicious payload to the semantic cache.
        """
        if not self.enabled:
            return

        try:
            doc_id = self._generate_id(text)
            
            # Check if it already exists
            existing = self.collection.get(ids=[doc_id])
            if existing and existing.get("ids") and len(existing["ids"]) > 0:
                return  # Already cached
                
            self.collection.add(
                documents=[text],
                metadatas=[{
                    "threat_type": threat_type,
                    "severity": severity,
                    "source_agent": source_agent,
                    "timestamp": time.time()
                }],
                ids=[doc_id]
            )
            print(f"[SemanticCache] Added new threat signature to Vector DB (type: {threat_type}).")
        except Exception as e:
            print(f"[SemanticCache] Error adding threat to cache: {e}")

    def check_threat(self, text: str, distance_threshold: float = 0.15) -> Optional[Dict[str, Any]]:
        """
        Checks if the text is semantically similar to a known threat.
        Distance threshold: 0.0 means identical, 1.0 means orthogonal.
        0.15 means >85% semantic similarity.
        """
        if not self.enabled:
            return None

        try:
            results = self.collection.query(
                query_texts=[text],
                n_results=1
            )
            
            if not results["documents"] or not results["documents"][0]:
                return None
                
            distance = results["distances"][0][0]
            if distance <= distance_threshold:
                metadata = results["metadatas"][0][0]
                matched_text = results["documents"][0][0]
                return {
                    "matched_text": matched_text,
                    "threat_type": metadata["threat_type"],
                    "severity": metadata["severity"],
                    "source_agent": metadata["source_agent"],
                    "distance": distance,
                    "similarity_score": 1.0 - distance
                }
        except Exception as e:
            print(f"[SemanticCache] Error querying cache: {e}")
            
        return None

    def add_allowlist(self, text: str, reason: str = "manual_override"):
        """
        Adds a known safe payload to the semantic allowlist.
        """
        if not self.enabled:
            return

        try:
            doc_id = self._generate_id(text)
            
            existing = self.allowlist_collection.get(ids=[doc_id])
            if existing and existing.get("ids") and len(existing["ids"]) > 0:
                return  # Already cached
                
            self.allowlist_collection.add(
                documents=[text],
                metadatas=[{
                    "reason": reason,
                    "timestamp": time.time()
                }],
                ids=[doc_id]
            )
            print(f"[SemanticCache] Added new safe signature to Allowlist Vector DB.")
        except Exception as e:
            print(f"[SemanticCache] Error adding allowlist to cache: {e}")

    def check_allowlist(self, text: str, distance_threshold: float = 0.10) -> Optional[Dict[str, Any]]:
        """
        Checks if the text is semantically similar to a known allowlisted text.
        Distance threshold is slightly stricter (0.10) to avoid falsely allowing attacks.
        """
        if not self.enabled:
            return None

        try:
            results = self.allowlist_collection.query(
                query_texts=[text],
                n_results=1
            )
            
            if not results["documents"] or not results["documents"][0]:
                return None
                
            distance = results["distances"][0][0]
            if distance <= distance_threshold:
                metadata = results["metadatas"][0][0]
                matched_text = results["documents"][0][0]
                return {
                    "matched_text": matched_text,
                    "reason": metadata.get("reason", "unknown"),
                    "distance": distance,
                    "similarity_score": 1.0 - distance
                }
        except Exception as e:
            print(f"[SemanticCache] Error querying allowlist cache: {e}")
            
        return None
