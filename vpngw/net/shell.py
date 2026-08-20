"""Thin, auditable subprocess wrapper.

Every command that touches the kernel goes through here so there is exactly one
place that logs what the daemon did. Commands are always passed as argument
lists - there is no shell, so no quoting bugs and no injection surface from
user-supplied slugs or IPs.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass

log = logging.getLogger("vpngw.shell")


class CommandError(RuntimeError):
    def __init__(self, result: "Result") -> None:
        self.result = result
        super().__init__(
            f"{' '.join(result.argv)} exited {result.rc}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


@dataclass
class Result:
    argv: list[str]
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def run(
    argv: list[str],
    *,
    check: bool = True,
    timeout: int = 30,
    input_text: str | None = None,
    quiet: bool = False,
) -> Result:
    if not quiet:
        log.debug("exec: %s", " ".join(argv))
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
    except FileNotFoundError as exc:
        raise CommandError(Result(argv, 127, "", str(exc))) from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(Result(argv, 124, "", f"timed out after {timeout}s")) from exc

    result = Result(argv, proc.returncode, proc.stdout, proc.stderr)
    if not result.ok and not quiet:
        log.warning("failed: %s -> rc=%d %s", " ".join(argv), result.rc,
                    result.stderr.strip())
    if check and not result.ok:
        raise CommandError(result)
    return result


def try_run(argv: list[str], **kw) -> Result:
    """Run a command whose failure is expected and harmless (idempotent
    deletes, probing for optional state)."""
    return run(argv, check=False, quiet=True, **kw)


REQUIRED_BINARIES = ["ip", "nft", "wg", "openvpn", "conntrack", "dnsmasq", "ping"]


def missing_binaries() -> list[str]:
    return [b for b in REQUIRED_BINARIES if shutil.which(b) is None]
