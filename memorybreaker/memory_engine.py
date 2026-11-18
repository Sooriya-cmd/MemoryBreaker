
import os
from pathlib import Path
from mem0 import Memory


# Project configuration
BASE_DIR = Path(__file__).resolve().parent.parent

CHROMA_PATH = BASE_DIR / "chroma_db"
COLLECTION_NAME = "memorybreaker_dev"

OLLAMA_URL = "http://localhost:11434"

LLM_MODEL = "llama3.1:8b"
EMBEDDING_MODEL = "nomic-embed-text"


def create_memory_engine() -> Memory:
    """
    Initialize Mem0 with local Ollama models
    and persistent ChromaDB storage.
    """

    CHROMA_PATH.mkdir(parents=True, exist_ok=True)

    config = {
        "llm": {
            "provider": "ollama",
            "config": {
                "model": LLM_MODEL,
                "temperature": 0.0,
                "ollama_base_url": OLLAMA_URL
            }
        },

        "embedder": {
            "provider": "ollama",
            "config": {
                "model": EMBEDDING_MODEL,
                "ollama_base_url": OLLAMA_URL
            }
        },

        "vector_store": {
            "provider": "chroma",
            "config": {
                "collection_name": COLLECTION_NAME,
                "path": str(CHROMA_PATH)
            }
        }
    }

    return Memory.from_config(config)


def add_memory(
    memory: Memory,
    content: str,
    user_id: str = "memorybreaker_user"
):
    """Store a memory without automatic inference."""

    return memory.add(
        content,
        user_id=user_id,
        infer=False
    )


def search_memory(
    memory: Memory,
    query: str,
    user_id: str = "memorybreaker_user"
):
    """Retrieve relevant memories."""

    return memory.search(
        query=query,
        filters={"user_id": user_id},
        top_k=10
    )


if __name__ == "__main__":

    print("Initializing MemoryBreaker Memory Engine...")

    memory = create_memory_engine()

    print("Memory engine initialized!")

    # Insert a test memory
    test_content = (
        "MemoryBreaker test record: "
        "The preferred programming language is Python."
    )

    print("\nStoring memory...")

    add_result = add_memory(memory, test_content)

    print("Storage result:", add_result)

    # Retrieve the memory
    print("\nSearching memory...")

    search_result = search_memory(
        memory,
        "Which programming language is preferred?"
    )

    print("\nRetrieved memories:")
    print(search_result)

    print("\nMemory engine test completed!")
