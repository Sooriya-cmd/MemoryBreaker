
from agent_memory_guard import MemoryGuard, Policy, Action

print("Initializing Memory Guard...")

guard = MemoryGuard(policy=Policy.strict())

print("\nMemory Guard initialized!")
print("Strict policy:", Policy.strict())
print("\nAvailable actions:")

for action in Action:
    print("-", action.name)

print("\nTesting a normal memory write...")

try:
    result = guard.write(
        key="test_preference",
        value="The user prefers Python programming.",
        source="agent"
    )

    print("Write result:", result)
    print("Action type:", type(result).__name__)

    print("\nReading the stored memory...")
    print(guard.read("test_preference"))

except Exception as error:
    print("Guard test raised an exception:")
    print(type(error).__name__, "-", error)
