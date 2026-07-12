"""Preconditions checked before a real research run starts. Not
indispensable, but cheap insurance against a human error (wrong dataset,
wrong profile, an analyzer version that silently drifted) producing data
that can't be compared to the intended baseline — better to fail fast
before spending the run's time budget than discover the mismatch after.
"""

from dataclasses import dataclass

from crawler.profiles import MeasurementProfile


@dataclass(frozen=True)
class RunGuard:
    expected_dataset_code: str
    expected_profile_name: str
    expected_sample_size: int
    expected_analyzer_versions: dict[str, str]


class GuardFailure(RuntimeError):
    pass


def check_guard(
    guard: RunGuard,
    dataset_code: str,
    profile: MeasurementProfile,
    domains: list[str],
    actual_analyzer_versions: dict[str, str],
) -> None:
    errors: list[str] = []

    if dataset_code != guard.expected_dataset_code:
        errors.append(
            f"dataset mismatch: expected {guard.expected_dataset_code!r}, got {dataset_code!r}"
        )
    if profile.name != guard.expected_profile_name:
        errors.append(
            f"profile mismatch: expected {guard.expected_profile_name!r}, got {profile.name!r}"
        )
    if len(domains) != guard.expected_sample_size:
        errors.append(
            f"sample size mismatch: expected {guard.expected_sample_size}, got {len(domains)}"
        )

    for name, expected_version in guard.expected_analyzer_versions.items():
        actual = actual_analyzer_versions.get(name)
        if actual != expected_version:
            errors.append(
                f"analyzer {name!r} version mismatch: expected {expected_version!r}, "
                f"got {actual!r}"
            )

    if errors:
        detail = "\n".join(f"  - {e}" for e in errors)
        raise GuardFailure(f"Run guard failed, refusing to start:\n{detail}")
