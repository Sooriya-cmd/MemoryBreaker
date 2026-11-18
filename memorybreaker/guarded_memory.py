
from mem0 import Memory
from agent_memory_guard import (
    MemoryGuard,
    Policy,
    Action,
    PolicyViolation,
)


def create_memory_guard() -> MemoryGuard:
    """Create a guard using the strict policy."""
    return MemoryGuard(policy=Policy.strict())


def guarded_write(
    guard: MemoryGuard,
    memory: Memory,
    key: str,
    content: str,
    user_id: str = "memorybreaker_user",
    source: str = "agent",
) -> dict:
    """
    Inspect content before storing it in Mem0.

    Only ALLOW and REDACT decisions are forwarded to Mem0.
    BLOCK and QUARANTINE decisions never reach Mem0.
    """

    try:
        action = guard.write(
            key=key,
            value=content,
            source=source,
        )

    except PolicyViolation as error:
        return {
            "status": "BLOCKED",
            "key": key,
            "rule": error.rule,
            "reason": str(error),
            "mem0_result": None,
        }

    if action == Action.QUARANTINE:
        return {
            "status": "QUARANTINED",
            "key": key,
            "action": action.value,
            "mem0_result": None,
        }

    if action not in (Action.ALLOW, Action.REDACT):
        return {
            "status": "REJECTED",
            "key": key,
            "action": action.value,
            "mem0_result": None,
        }

    # Read the guard-approved version.
    # This is essential for REDACT decisions.
    approved_content = guard.read(key, default=None)

    if approved_content is None:
        raise RuntimeError(
            f"Guard approved '{key}', but no approved content was returned."
        )

    # Only approved content reaches Mem0.
    mem0_result = memory.add(
        approved_content,
        user_id=user_id,
        infer=False,
        metadata={
            "guard_key": key,
            "guard_action": action.value,
            "source": source,
        },
    )

    return {
        "status": "STORED",
        "key": key,
        "action": action.value,
        "mem0_result": mem0_result,
    }


if __name__ == "__main__":
    from memorybreaker.memory_engine import create_memory_engine

    print("Initializing MemoryBreaker Guarded Memory...")

    guard = create_memory_guard()
    memory = create_memory_engine()

    result = guarded_write(
        guard=guard,
        memory=memory,
        key="guarded_test_001",
        content="MemoryBreaker guarded integration test: Python is useful.",
    )

    print("\nGuarded write result:")
    print(result)
