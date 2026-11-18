
import inspect
import importlib.metadata

from mem0 import Memory
from agent_memory_guard import (
    MemoryGuard,
    Policy,
    PolicyViolation,
    Action
)

print("\n=== PACKAGE VERSIONS ===")

for package in [
    "mem0ai",
    "chromadb",
    "agent-memory-guard",
    "requests"
]:
    print(package, importlib.metadata.version(package))


print("\n=== MEM0 API ===")

for method in [
    Memory.from_config,
    Memory.add,
    Memory.search
]:
    print(f"\n{method.__qualname__}")
    print(inspect.signature(method))


print("\n=== OWASP GUARD API ===")

print("Guard write:", inspect.signature(MemoryGuard.write))
print("Guard read:", inspect.signature(MemoryGuard.read))
print("Strict policy:", inspect.signature(Policy.strict))

print("\n=== AVAILABLE ACTIONS ===")

print(getattr(Action, "__members__", Action))

print("\n=== DEPENDENCY INSPECTION COMPLETE ===")
