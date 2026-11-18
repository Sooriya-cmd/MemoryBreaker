
import requests


OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.1:8b"


def call_ollama(
    prompt: str,
    model: str = DEFAULT_MODEL
) -> str:
    """
    Send a prompt to a locally running Ollama model
    and return its generated response.
    """

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0
        }
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120
        )

        response.raise_for_status()

        data = response.json()

        if "response" not in data:
            raise ValueError("Invalid Ollama response")

        return data["response"].strip()

    except requests.RequestException as error:
        raise RuntimeError(
            f"Ollama connection failed: {error}"
        ) from error


if __name__ == "__main__":
    answer = call_ollama(
        "Explain AI memory poisoning in two sentences."
    )

    print("\n--- Ollama Response ---")
    print(answer)
