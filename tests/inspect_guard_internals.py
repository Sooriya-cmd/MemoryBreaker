
import inspect
from agent_memory_guard import MemoryGuard

guard = MemoryGuard()

methods = ["_write_impl", "_run", "read"]

for method_name in methods:
    print("\n" + "=" * 65)
    print(f"METHOD: {method_name}")
    print("=" * 65)

    method = getattr(guard, method_name, None)

    if method is None:
        print("Method not found.")
        continue

    try:
        print(inspect.getsource(method))
    except (OSError, TypeError) as error:
        print("Could not inspect:", error)
