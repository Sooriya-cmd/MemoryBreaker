
import inspect
import agent_memory_guard
from agent_memory_guard import MemoryGuard

print("PACKAGE LOCATION")
print(agent_memory_guard.__file__)

print("\nMEMORY GUARD WRITE IMPLEMENTATION")
print(inspect.getsource(MemoryGuard.write))

print("\nEXCEPTION CLASSES")

for name, obj in inspect.getmembers(agent_memory_guard):
    if inspect.isclass(obj) and (
        "exception" in name.lower()
        or "violation" in name.lower()
    ):
        print(f"\n{name}")
        try:
            print(inspect.getsource(obj))
        except (OSError, TypeError):
            print("Source unavailable")
