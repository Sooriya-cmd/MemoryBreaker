
import inspect
from agent_memory_guard import MemoryGuard, Policy

guard = MemoryGuard(policy=Policy.strict())

print("REGISTERED DETECTORS")
print("=" * 60)

for detector in guard._detectors:
    print("\nDetector:", getattr(detector, "name", "Unknown"))
    print("Class:", type(detector).__name__)
    print("Module:", type(detector).__module__)

    print("\nInspection method:")

    try:
        print(inspect.getsource(detector.inspect))
    except (OSError, TypeError, AttributeError):
        print("Source unavailable")

print("\n" + "=" * 60)
print("TESTING DETECTORS AGAINST EMAIL")
print("=" * 60)

key = "contact_note"
value = "Contact alice@example.com for testing."

for detector in guard._detectors:
    try:
        result = detector.inspect(key, value, operation="write")

        print("\nDetector:", getattr(detector, "name", type(detector).__name__))
        print("Matched:", result.matched)
        print("Severity:", result.severity)
        print("Message:", result.message)

    except Exception as error:
        print("\nDetector error:", type(error).__name__, error)
