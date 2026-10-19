"""LLM access behind a small interface so the workflow can be tested without a model server."""

from __future__ import annotations

from typing import Protocol, TypeVar

from pydantic import BaseModel

from cybot.config import Settings

T = TypeVar("T", bound=BaseModel)


class StructuredLLM(Protocol):
    model_name: str

    def generate(self, schema: type[T], system: str, prompt: str) -> T:
        """Return an instance of ``schema`` produced by the model."""
        ...


class OllamaLLM:
    """Local models served by Ollama, constrained to a JSON schema per call."""

    def __init__(self, settings: Settings) -> None:
        from langchain_ollama import ChatOllama

        self.model_name = settings.ollama_model
        self._chat = ChatOllama(
            model=settings.ollama_model,
            base_url=settings.ollama_base_url,
            temperature=settings.llm_temperature,
            num_ctx=settings.ollama_num_ctx,
            client_kwargs={"timeout": settings.llm_timeout_seconds},
        )

    def generate(self, schema: type[T], system: str, prompt: str) -> T:
        runnable = self._chat.with_structured_output(schema, method="json_schema")
        result = runnable.invoke([("system", system), ("human", prompt)])
        if result is None:
            raise ValueError(f"Model returned no parseable {schema.__name__}")
        return result if isinstance(result, schema) else schema.model_validate(result)
