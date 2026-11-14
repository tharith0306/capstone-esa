from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from app.schemas.event import EventSource


class Collector(ABC):
    """Pulls raw records for a time window. Collectors never normalize; that is Layer 3's job."""

    name: str
    source: EventSource

    @abstractmethod
    def collect(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]: ...
