
from agent_memory_guard import MemoryGuard, Policy, Action

guard = MemoryGuard(policy=Policy.strict())

key = "contact_note"

content = (
    "The test user's email address is "
    "alice@example.com. This is synthetic test data."
)

print("Original content:")
print(content)

print("\nSubmitting memory to guard...")

try:
    action = guard.write(
        key=key,
        value=content,
        source="agent"
    )

    print("\nGuard action:", action)

    if action == Action.REDACT:
        print("\nReading the approved content:")
        approved_content = guard.read(key)
        print(approved_content)

        print("\nOriginal email still present:",
              "alice@example.com" in str(approved_content))

    elif action == Action.ALLOW:
        print("Content was allowed without redaction.")

    elif action == Action.QUARANTINE:
        print("Content was quarantined. It must not enter Mem0.")

except Exception as error:
    print("\nGuard exception:", type(error).__name__)
    print("Details:", error)

