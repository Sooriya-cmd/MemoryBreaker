
from agent_memory_guard import MemoryGuard, Policy

guard = MemoryGuard(policy=Policy.strict())

detector = next(
    d for d in guard._detectors
    if getattr(d, "name", "") == "sensitive_data"
)

print("DETECTOR CLASS:", type(detector).__name__)
print("\nREGISTERED PATTERNS:")

for label, pattern in detector._patterns.items():
    print(f"\nCategory: {label}")
    print(f"Pattern: {pattern.pattern}")

print("\nTESTING EMAIL DETECTION:")

test_values = [
    "alice@example.com",
    "Contact alice@example.com",
    "The test user's email address is alice@example.com.",
]

for value in test_values:
    result = detector.inspect(
        "contact_note",
        value,
        operation="write"
    )

    print(f"\nInput: {value}")
    print("Matched:", result.matched)
    print("Metadata:", result.metadata)
