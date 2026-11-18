
from agent_memory_guard import MemoryGuard, Policy

guard = MemoryGuard(policy=Policy.strict())

detector = next(
    d for d in guard._detectors
    if getattr(d, "name", "") == "sensitive_data"
)

test_values = [
    "Example API key: sk-abcdefghijklmnopqrstuvwxyz123456",
    "Example GitHub token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
]

for value in test_values:
    result = detector.inspect(
        "secret_test",
        value,
        operation="write"
    )

    print("\nInput:", value)
    print("Matched:", result.matched)
    print("Metadata:", result.metadata)

    if result.matched:
        try:
            action = guard.write(
                key="secret_test",
                value=value,
                source="agent"
            )
            print("Guard action:", action)
            print("Guard read:", guard.read("secret_test"))

        except Exception as error:
            print("Guard exception:", type(error).__name__, error)
