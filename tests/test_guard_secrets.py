
import pytest

from agent_memory_guard import MemoryGuard, Policy, Action


@pytest.mark.parametrize(
    "secret, expected_marker",
    [
        (
            "sk-" + ("a" * 32),
            "[REDACTED:openai_key]",
        ),
        (
            "ghp_" + ("A" * 36),
            "[REDACTED:github_token]",
        ),
    ],
)
def test_sensitive_credentials_are_detected_and_redacted(
    secret,
    expected_marker,
):
    guard = MemoryGuard(policy=Policy.strict())

    # Inspect the sensitive-data detector.
    detector = next(
        detector
        for detector in guard._detectors
        if getattr(detector, "name", "") == "sensitive_data"
    )

    result = detector.inspect(
        "secret_test",
        secret,
        operation="write",
    )

    assert result.matched is True

    # Verify that the guard redacts the credential.
    action = guard.write(
        key="secret_test",
        value=secret,
        source="agent",
    )

    assert action == Action.REDACT

    redacted_value = guard.read("secret_test")

    assert expected_marker in redacted_value
    assert secret not in redacted_value
