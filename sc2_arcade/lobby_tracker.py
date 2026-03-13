"""
SC2 Arcade Lobby Tracker
=========================
Stateful in-memory tracker that consumes decoded signals and maintains
a live map of open lobbies.
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from .signal_decoder import (
    SignalBase, SignalKind,
    SignalInit, SignalLbls, SignalLbcr, SignalLbrm, SignalLbud,
    SignalLbpv, SignalLbpa, SignalLbpe, LobbySlot,
)


@dataclass
class OpenLobby:
    lobby_id:           str
    map_handle:         str
    ext_mod_handle:     str
    multi_mod_handle:   str
    map_variant_idx:    int
    lobby_name:         str
    host_name:          str
    slots_humans_taken: int
    slots_humans_total: int
    slots:              list[LobbySlot] = field(default_factory=list)
    teams_number:       int = 0
    first_seen:         float = field(default_factory=time.time)
    last_seen:          float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["slots"] = [
            {
                "kind":    s["kind"],
                "team":    s["team"],
                "name":    s["name"],
                "profile": s["profile"],
            }
            for s in d["slots"]
        ]
        return d


class LobbyTracker:
    """
    Processes a stream of signals and maintains open_lobbies.
    Feed signals via process(signal).
    """

    def __init__(self):
        self.open_lobbies: dict[str, OpenLobby] = {}
        self.session_bucket: Optional[str] = None
        self._total_created  = 0
        self._total_removed  = 0

    def process(self, sig: SignalBase) -> None:
        now = time.time()

        if sig.kind == SignalKind.INIT:
            assert isinstance(sig, SignalInit)
            self.session_bucket = sig.bucket_id
            self.open_lobbies.clear()

        elif sig.kind == SignalKind.LBCR:
            assert isinstance(sig, SignalLbcr)
            self.open_lobbies[sig.lobby_id] = OpenLobby(
                lobby_id=sig.lobby_id,
                map_handle=sig.map_handle,
                ext_mod_handle=sig.ext_mod_handle,
                multi_mod_handle=sig.multi_mod_handle,
                map_variant_idx=sig.map_variant_idx,
                lobby_name=sig.lobby_name,
                host_name=sig.host_name,
                slots_humans_taken=sig.slots_humans_taken,
                slots_humans_total=sig.slots_humans_total,
                first_seen=now,
                last_seen=now,
            )
            self._total_created += 1

        elif sig.kind == SignalKind.LBRM:
            assert isinstance(sig, SignalLbrm)
            self.open_lobbies.pop(sig.lobby_id, None)
            self._total_removed += 1

        elif sig.kind == SignalKind.LBUD:
            assert isinstance(sig, SignalLbud)
            lobby = self.open_lobbies.get(sig.lobby_id)
            if lobby:
                if sig.lobby_name is not None:
                    lobby.lobby_name = sig.lobby_name
                if sig.host_name is not None:
                    lobby.host_name = sig.host_name
                if sig.slots_humans_taken is not None:
                    lobby.slots_humans_taken = sig.slots_humans_taken
                if sig.slots_humans_total is not None:
                    lobby.slots_humans_total = sig.slots_humans_total
                lobby.last_seen = now

        elif sig.kind == SignalKind.LBPV:
            assert isinstance(sig, SignalLbpv)
            lobby = self.open_lobbies.get(sig.lobby_id)
            if lobby:
                lobby.slots        = sig.slots
                lobby.teams_number = sig.teams_number
                lobby.last_seen    = sig.timestamp or now

        elif sig.kind == SignalKind.LBPE:
            assert isinstance(sig, SignalLbpe)
            lobby = self.open_lobbies.get(sig.lobby_id)
            if lobby:
                # Merge extended profile data into existing slots if we have them
                if sig.slots:
                    lobby.slots = sig.slots
                lobby.last_seen = now

        elif sig.kind == SignalKind.LBPA:
            assert isinstance(sig, SignalLbpa)
            lobby = self.open_lobbies.get(sig.lobby_id)
            if lobby:
                lobby.last_seen = now

    def process_many(self, signals: list[SignalBase]) -> None:
        for sig in signals:
            self.process(sig)

    def get_open(self, stale_threshold: float = 120.0) -> list[OpenLobby]:
        """Return open lobbies, optionally filtering out stale ones."""
        now = time.time()
        return [
            lob for lob in self.open_lobbies.values()
            if (now - lob.last_seen) < stale_threshold
        ]

    def stats(self) -> dict:
        return {
            "open":    len(self.open_lobbies),
            "created": self._total_created,
            "removed": self._total_removed,
            "bucket":  self.session_bucket,
        }
