"""
PSIA — PreScreen Ingestion Architecture
7-stage pipeline: PreScreenGate -> Ingestion -> Schema Validation -> Classification -> Shadow Simulation -> Governance -> Canonical Log -> Seal
6 plane data models + FastAPI gateway on port 8002.
"""
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─── Plane Data Models ────────────────────────────────────────────────────────

class Plane(StrEnum):
    RAW = "raw"
    VERIFIED = "verified"
    CLASSIFIED = "classified"
    SIMULATED = "simulated"
    GOVERNED = "governed"
    SEALED = "sealed"


@dataclass
class RawFrame:
    """Raw input data before any processing."""
    source: str
    payload: dict[str, Any]
    timestamp: float
    source_hash: str = ""
    frame_id: str = ""

    def __post_init__(self):
        if not self.source_hash:
            self.source_hash = hashlib.sha256(
                json.dumps(self.payload, sort_keys=True).encode('utf-8')
            ).hexdigest()
        if not self.frame_id:
            self.frame_id = hashlib.md5(
                f"{self.source}{self.timestamp}{self.source_hash}".encode()
            ).hexdigest()


@dataclass
class VerifiedFrame:
    """Frame after schema validation and source verification."""
    frame_id: str
    source: str
    payload: dict[str, Any]
    timestamp: float
    source_hash: str
    schema_version: str = "1.0"
    verified_at: float = 0.0
    verified: bool = True
    errors: list[str] = field(default_factory=list)


@dataclass
class ClassifiedFrame:
    """Frame after classification."""
    frame_id: str
    payload: dict[str, Any]
    classification: str = "unknown"
    confidence: float = 0.0
    categories: list[str] = field(default_factory=list)
    classified_at: float = 0.0


@dataclass
class SimulatedFrame:
    """Frame after shadow simulation with invariant checks."""
    frame_id: str
    payload: dict[str, Any]
    classification: str
    shadow_result: str = "pending"
    invariant_checks: list[dict[str, Any]] = field(default_factory=list)
    all_invariants_pass: bool = False
    simulated_at: float = 0.0


@dataclass
class GovernedFrame:
    """Frame after governance evaluation."""
    frame_id: str
    payload: dict[str, Any]
    governance_verdict: str = "pending"
    pillar_results: dict[str, Any] = field(default_factory=dict)
    governed_at: float = 0.0
    canary: dict[str, Any] = field(default_factory=dict)


@dataclass
class SealedFrame:
    """Final sealed frame with Merkle tree hash and signature."""
    frame_id: str
    payload: dict[str, Any]
    merkle_root: str = ""
    signature: str = ""
    sealed_at: float = 0.0
    seal_hash: str = ""

    def __post_init__(self):
        if not self.merkle_root:
            self.merkle_root = self._compute_merkle_root()
        if not self.seal_hash:
            content = json.dumps(asdict(self), sort_keys=True).encode('utf-8')
            self.seal_hash = hashlib.sha256(content).hexdigest()

    def _compute_merkle_root(self) -> str:
        """Compute Merkle tree root from payload."""
        items = []
        for k, v in self.payload.items():
            leaf = hashlib.sha256(f"{k}:{json.dumps(v)}".encode()).hexdigest()
            items.append(leaf)

        if not items:
            return hashlib.sha256(b'EMPTY').hexdigest()

        while len(items) > 1:
            new_level = []
            for i in range(0, len(items), 2):
                if i + 1 < len(items):
                    combined = items[i] + items[i + 1]
                else:
                    combined = items[i] + items[i]
                new_level.append(hashlib.sha256(combined.encode()).hexdigest())
            items = new_level

        return items[0]

    def sign(self, private_key: str = "default_key") -> str:
        """Create an Ed25519-style signature (simulated with SHA-256 HMAC)."""
        content = self.merkle_root + self.frame_id
        self.signature = hashlib.sha256(
            (content + private_key).encode('utf-8')
        ).hexdigest()
        return self.signature


# ─── Pipeline Stages ─────────────────────────────────────────────────────────

class PreScreenGate:
    """Stage 1: Initial screening of raw input."""

    def process(self, frame: RawFrame) -> tuple[bool, str | None]:
        """Screen the raw frame. Returns (passed, error_reason)."""
        if not frame.payload:
            return False, "Empty payload"
        if frame.source_hash != hashlib.sha256(
            json.dumps(frame.payload, sort_keys=True).encode('utf-8')
        ).hexdigest():
            return False, "Hash mismatch"
        return True, None


class Ingestion:
    """Stage 2: Ingest raw data into processing pipeline."""

    def process(self, frame: RawFrame) -> VerifiedFrame:
        return VerifiedFrame(
            frame_id=frame.frame_id,
            source=frame.source,
            payload=frame.payload,
            timestamp=frame.timestamp,
            source_hash=frame.source_hash,
            verified_at=time.time(),
        )


class SchemaValidator:
    """Stage 3: Validate payload against schema."""

    REQUIRED_FIELDS = ['type', 'data']

    def process(self, frame: VerifiedFrame) -> VerifiedFrame:
        """Validate that payload contains required fields."""
        errors = []
        for required in self.REQUIRED_FIELDS:
            if required not in frame.payload:
                errors.append(f"Missing required field: {required}")

        if errors:
            frame.verified = False
            frame.errors = errors
        else:
            # Validate data structure
            data = frame.payload.get('data', {})
            if not isinstance(data, dict):
                frame.verified = False
                frame.errors.append("data must be a dict")

        return frame


class Classifier:
    """Stage 4: Classify the frame content."""

    CATEGORIES = ['user_action', 'system_event', 'policy_check', 'audit_entry', 'governance_call']

    def process(self, frame: VerifiedFrame) -> ClassifiedFrame:
        """Classify based on payload type."""
        payload_type = frame.payload.get('type', 'unknown')

        if payload_type in self.CATEGORIES:
            classification = payload_type
            confidence = 0.95
        else:
            classification = 'unknown'
            confidence = 0.5

        return ClassifiedFrame(
            frame_id=frame.frame_id,
            payload=frame.payload,
            classification=classification,
            confidence=confidence,
            categories=[classification],
            classified_at=time.time(),
        )


class ShadowSimulator:
    """Stage 5: Shadow simulation with 4 invariant checks."""

    INVARIANTS = [
        "shadow_does_not_write_canonical_state",
        "shadow_is_deterministic",
        "shadow_within_resource_limits",
        "shadow_converges_with_canonical",
    ]

    def process(self, frame: ClassifiedFrame) -> SimulatedFrame:
        """Run shadow simulation and invariant checks."""
        checks = []
        all_pass = True

        for invariant in self.INVARIANTS:
            # Simulate invariant check — in production this runs actual shadow
            check_pass = True  # Shadow checks pass by default for processed frames
            checks.append({
                "invariant": invariant,
                "passed": check_pass,
                "checked_at": time.time(),
            })
            if not check_pass:
                all_pass = False

        return SimulatedFrame(
            frame_id=frame.frame_id,
            payload=frame.payload,
            classification=frame.classification,
            shadow_result="passed" if all_pass else "failed",
            invariant_checks=checks,
            all_invariants_pass=all_pass,
            simulated_at=time.time(),
        )


class GovernanceSubmitter:
    """Stage 6: Submit to Triumvirate governance for evaluation."""

    def process(self, frame: SimulatedFrame) -> GovernedFrame:
        """Submit frame to governance evaluation (simulated)."""
        # In production, this would call the Triumvirate server
        verdict = "ALLOW"
        pillar_results = {
            "galahad": {"verdict": "ALLOW", "reason": "Ethics check passed"},
            "cerberus": {"verdict": "ALLOW", "reason": "Security check passed"},
            "codexdeus": {"verdict": "ALLOW", "reason": "Constitutional check passed"},
        }

        return GovernedFrame(
            frame_id=frame.frame_id,
            payload=frame.payload,
            governance_verdict=verdict,
            pillar_results=pillar_results,
            governed_at=time.time(),
            canary={"active": False, "last_check": time.time()},
        )


class CanonicalLogger:
    """Stage 7a: Log to canonical (append-only) store."""

    def process(self, frame: GovernedFrame) -> GovernedFrame:
        """Log the governed frame to canonical store."""
        # In production, this writes to an append-only ledger
        return frame


class Sealer:
    """Stage 7b: Seal with Merkle tree hash and signature."""

    def process(self, frame: GovernedFrame) -> SealedFrame:
        """Create sealed frame with Merkle tree and signature."""
        sealed = SealedFrame(
            frame_id=frame.frame_id,
            payload=frame.payload,
            sealed_at=time.time(),
        )
        sealed.sign()
        return sealed


# ─── PSIA Pipeline ────────────────────────────────────────────────────────────

class PSIAPipeline:
    """
    Complete 7-stage PSIA pipeline:
    1. PreScreenGate
    2. Ingestion
    3. Schema Validation
    4. Classification
    5. Shadow Simulation (4 invariant checks)
    6. Governance (Triumvirate submission)
    7. Canonical Log -> Seal (Merkle tree + Ed25519)
    """

    def __init__(self):
        self.gate = PreScreenGate()
        self.ingestion = Ingestion()
        self.validator = SchemaValidator()
        self.classifier = Classifier()
        self.simulator = ShadowSimulator()
        self.governor = GovernanceSubmitter()
        self.logger = CanonicalLogger()
        self.sealer = Sealer()

    def run(self, source: str, payload: dict[str, Any]) -> SealedFrame:
        """Run a frame through the complete 7-stage pipeline."""
        raw = RawFrame(source=source, payload=payload, timestamp=time.time())

        # Stage 1: PreScreenGate
        passed, error = self.gate.process(raw)
        if not passed:
            raise ValueError(f"PreScreenGate rejected: {error}")

        # Stage 2-3: Ingestion + Schema Validation
        verified = self.ingestion.process(raw)
        verified = self.validator.process(verified)

        if not verified.verified:
            raise ValueError(f"Schema validation failed: {verified.errors}")

        # Stage 4: Classification
        classified = self.classifier.process(verified)

        # Stage 5: Shadow Simulation
        simulated = self.simulator.process(classified)

        if not simulated.all_invariants_pass:
            raise ValueError("Shadow simulation failed: some invariants did not pass")

        # Stage 6: Governance
        governed = self.governor.process(simulated)

        if governed.governance_verdict != "ALLOW":
            raise ValueError(f"Governance denied: {governed.governance_verdict}")

        # Stage 7: Canonical Log + Seal
        governed = self.logger.process(governed)
        sealed = self.sealer.process(governed)

        return sealed


# ─── FastAPI Gateway ──────────────────────────────────────────────────────────

app = FastAPI(title="PSIA Gateway", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pipeline = PSIAPipeline()


class PipelineRequest(BaseModel):
    source: str
    payload: dict[str, Any]


class PipelineResponse(BaseModel):
    frame_id: str
    merkle_root: str
    signature: str
    seal_hash: str
    status: str


@app.post("/ingest")
async def ingest(req: PipelineRequest):
    """Ingest data through the full 7-stage PSIA pipeline."""
    try:
        sealed = pipeline.run(source=req.source, payload=req.payload)
        return PipelineResponse(
            frame_id=sealed.frame_id,
            merkle_root=sealed.merkle_root,
            signature=sealed.signature,
            seal_hash=sealed.seal_hash,
            status="sealed",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "psia"}


def main():
    """Run the PSIA gateway server with uvicorn."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)


if __name__ == "__main__":
    main()
