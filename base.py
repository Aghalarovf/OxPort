from dataclasses import dataclass
from typing import Optional


@dataclass
class AnonymousCheckResult:
    service: str
    host: str
    port: int
    protocol: str
    vulnerable: bool
    detail: str
    error: Optional[str] = None


def ok(service: str, host: str, port: int, protocol: str, detail: str) -> AnonymousCheckResult:
    return AnonymousCheckResult(service=service, host=host, port=port, protocol=protocol, vulnerable=True, detail=detail)


def no(service: str, host: str, port: int, protocol: str, detail: str) -> AnonymousCheckResult:
    return AnonymousCheckResult(service=service, host=host, port=port, protocol=protocol, vulnerable=False, detail=detail)


def failed(service: str, host: str, port: int, protocol: str, error: str) -> AnonymousCheckResult:
    return AnonymousCheckResult(service=service, host=host, port=port, protocol=protocol, vulnerable=False, detail="check could not complete", error=error)
