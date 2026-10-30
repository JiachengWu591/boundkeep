"""A short-lived memory of model verdicts (PROJECT_SPEC.md §9.6).

The key is a hash of everything the model was shown and by whom: the backend, the model, the
transport, the system prompt's hash and the gated user message itself (which carries the
normalized action, the task intent summary, the taint bits and the source names). That is the
spec's key and slightly more, so a hit is only ever an identical question to the same model.

Only successful, schema-valid verdicts are kept (a timeout now says nothing about a minute later);
the final verdict is not cached, the code rules on the cached model verdict again. Memory only: no
file, so no key and no user text ever reaches the disk through it. Bounded (least recently used
first out) and thread-safe. A TTL of 0 turns it off.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from collections.abc import Callable

from boundkeep.audit.backends.base import AuditResult

MAX_ENTRIES = 2048


def cache_key(*, backend: str, model: str, transport: str, prompt_hash: str, content: str) -> str:
    h = hashlib.sha256()
    for part in (backend, model, transport, prompt_hash, content):
        data = part.encode("utf-8", "surrogatepass")
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


class VerdictCache:
    def __init__(
        self,
        ttl_s: float,
        *,
        max_entries: int = MAX_ENTRIES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = max(0.0, ttl_s)
        self._max = max(1, max_entries)
        self._clock = clock
        self._lock = threading.Lock()
        self._items: OrderedDict[str, tuple[float, AuditResult]] = OrderedDict()

    @property
    def enabled(self) -> bool:
        return self._ttl > 0

    def get(self, key: str) -> AuditResult | None:
        if not self.enabled:
            return None
        now = self._clock()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            stored, result = item
            if now - stored >= self._ttl:
                del self._items[key]
                return None
            self._items.move_to_end(key)
            return result

    def put(self, key: str, result: AuditResult) -> None:
        if not self.enabled:
            return
        now = self._clock()
        with self._lock:
            self._items[key] = (now, result)
            self._items.move_to_end(key)
            while len(self._items) > self._max:
                self._items.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
