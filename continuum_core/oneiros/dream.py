"""Deterministic, user-triggered dream consolidation.

The dream reviews a bounded set of unprocessed episodes, proposes structured
candidates, and flags contradictions and stale facts.  It never promotes a
candidate to confirmed memory and never overwrites an older value.
"""

from __future__ import annotations

from typing import Any

from ..common.config import ContinuumConfig
from ..common.ids import new_id
from ..common.time import utc_now_iso
from ..spine.store import SpineStore
from .memory import MemoryService, extract_fact_candidate


class DreamService:
    def __init__(self, store: SpineStore, config: ContinuumConfig | None = None):
        self.store = store
        self.config = (config or ContinuumConfig()).clamped()
        self.memory = MemoryService(store, self.config)

    def run(self) -> dict[str, Any]:
        episodes = self.store.unprocessed_episodes(limit=self.config.dream_episode_limit)
        if not episodes:
            last = self.store.last_dream_run()
            self.store.append_event(
                "dream_skipped",
                "Dream skipped: no unprocessed episodes",
                details={
                    "reason": "no_new_episodes",
                    "last_run_id": last["id"] if last else None,
                },
                idempotency_key=f"dream-skip:{last['id'] if last else 'none'}",
            )
            return {
                "ok": True,
                "status": "no_new_episodes",
                "idempotent": True,
                "episodes_processed": 0,
                "candidates_created": 0,
                "contradictions": [],
                "stale_facts": self.store.list_stale_facts(days=30),
                "last_run": last,
            }

        run_id = new_id("dream")
        started_at = utc_now_iso()
        self.store.append_event(
            "dream_started",
            f"Dream started for {len(episodes)} episode(s)",
            details={"run_id": run_id, "episodes": len(episodes)},
            idempotency_key=f"dream-start:{run_id}",
        )
        created: list[dict[str, Any]] = []
        contradictions: list[dict[str, Any]] = []
        not_retained: list[dict[str, Any]] = []
        already_extracted: list[str] = []
        try:
            for episode in episodes:
                existing = self.store.find_fact_by_episode(episode["id"])
                if existing is not None:
                    already_extracted.append(episode["id"])
                    self.store.mark_episodes_processed([episode["id"]], run_id)
                    continue
                if episode.get("trust_label") not in (None, "", "USER_AUTHORED", "PLUGIN_GENERATED"):
                    not_retained.append(
                        {
                            "episode_id": episode["id"],
                            "reason": "source trust is not user-authored",
                        }
                    )
                    self.store.mark_episodes_processed([episode["id"]], run_id)
                    continue
                candidate = extract_fact_candidate(episode.get("user_excerpt", ""))
                if candidate is None:
                    not_retained.append(
                        {
                            "episode_id": episode["id"],
                            "reason": "no reviewable fact extracted",
                        }
                    )
                    self.store.mark_episodes_processed([episode["id"]], run_id)
                    continue
                contradiction = self.memory._find_contradiction(candidate)
                fact = self.store.add_memory_fact(
                    fact_key=candidate["fact_key"],
                    value=candidate["value"],
                    status="candidate",
                    confidence=candidate["confidence"],
                    source_ref=episode.get("source_ref"),
                    source_event_id=episode.get("event_id"),
                    episode_id=episode["id"],
                    provenance=episode.get("trust_label") or "USER_AUTHORED",
                    notes=f"dream:{run_id}",
                    contradicts_fact_id=contradiction["id"] if contradiction else None,
                    event_type="memory_candidate_created",
                )
                created.append(fact)
                if contradiction is not None:
                    contradictions.append(
                        {
                            "candidate_id": fact["id"],
                            "fact_key": fact["fact_key"],
                            "candidate_value": fact["value"],
                            "existing_fact_id": contradiction["id"],
                            "existing_value": contradiction["value"],
                            "existing_status": contradiction["status"],
                        }
                    )
                self.store.mark_episodes_processed([episode["id"]], run_id)
        except Exception as exc:  # noqa: BLE001 - surfaced as a safe user message
            self.store.append_event(
                "dream_skipped",
                "Dream failed before completion; no new candidates were promoted",
                details={"run_id": run_id, "error_type": type(exc).__name__},
                idempotency_key=f"dream-failed:{run_id}",
            )
            return {
                "ok": False,
                "status": "failed",
                "run_id": run_id,
                "error": "Dream consolidation failed. No candidates were promoted.",
                "episodes_processed": len(already_extracted),
                "candidates_created": len(created),
                "contradictions": contradictions,
            }

        first_event, last_event = self.store.event_row_range()
        previous = self.store.last_dream_run()
        from_event_id = int(previous["to_event_id"]) if previous and previous.get("to_event_id") else first_event
        stale = self.store.list_stale_facts(days=30)
        report = {
            "run_id": run_id,
            "started_at": started_at,
            "completed_at": utc_now_iso(),
            "episodes_seen": len(episodes),
            "episodes_processed": len(episodes),
            "candidates_created": len(created),
            "already_extracted": len(already_extracted),
            "contradictions": contradictions,
            "stale_facts": [
                {
                    "id": fact["id"],
                    "fact_key": fact["fact_key"],
                    "value": fact["value"],
                    "last_observed_utc": fact["last_observed_utc"],
                }
                for fact in stale
            ],
            "not_retained": not_retained,
            "candidate_ids": [fact["id"] for fact in created],
            "policy": "deterministic extraction; review required",
        }
        run = self.store.record_dream_run(
            status="completed",
            from_event_id=from_event_id,
            to_event_id=last_event,
            episodes_processed=len(episodes),
            candidates_created=len(created),
            contradictions=contradictions,
            report=report,
            run_id=run_id,
            started_at=started_at,
        )
        return {
            "ok": True,
            "status": "completed",
            "run": run,
            "report": report,
            "candidates": created,
            "contradictions": contradictions,
            "stale_facts": report["stale_facts"],
            "not_retained": not_retained,
        }
