from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EndpointSignal:
    url: str
    method: str
    source: str          # "param", "path", "header", "form", "content-type"
    vector: str
    weight: int
    detail: str          # human-readable reason


@dataclass
class PageResult:
    url: str
    status: int
    content_type: str
    headers: dict[str, str]
    forms: list[dict]    # each: {action, method, fields: [{name, type}]}
    params: list[str]
    links: list[str]
    signals: list[EndpointSignal] = field(default_factory=list)


@dataclass
class VectorScore:
    vector: str
    score: int
    signals: list[EndpointSignal] = field(default_factory=list)

    @property
    def confidence(self) -> str:
        if self.score >= 6:
            return "HIGH"
        if self.score >= 3:
            return "MEDIUM"
        return "LOW"
