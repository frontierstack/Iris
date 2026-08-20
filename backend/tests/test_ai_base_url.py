"""Base-URL normalisation for OpenAI-compatible endpoints.

Regression: Iris appended "/chat/completions" to whatever was configured, so a base URL without the
"/v1" segment (which is how most providers document theirs) produced a bare 404 from the gateway.
"""
from __future__ import annotations

import pytest

from app.ai.client import DEFAULT_BASE_URL, LLMClient, normalize_base_url


@pytest.mark.parametrize(
    "raw,expected",
    [
        # empty falls back to the OpenAI default
        ("", DEFAULT_BASE_URL),
        ("   ", DEFAULT_BASE_URL),
        # the /v1 the user left off is added
        ("https://api.openai.com", "https://api.openai.com/v1"),
        ("https://api.openai.com/", "https://api.openai.com/v1"),
        ("https://openrouter.ai/api", "https://openrouter.ai/api/v1"),
        ("http://localhost:11434", "http://localhost:11434/v1"),
        ("https://api.groq.com/openai", "https://api.groq.com/openai/v1"),
        ("https://my-proxy.corp/llm/", "https://my-proxy.corp/llm/v1"),
        # already correct → untouched
        ("https://api.openai.com/v1", "https://api.openai.com/v1"),
        ("https://openrouter.ai/api/v1", "https://openrouter.ai/api/v1"),
        # a pasted full endpoint is trimmed back to the base
        ("https://api.openai.com/v1/chat/completions", "https://api.openai.com/v1"),
        ("https://host/v1/completions", "https://host/v1"),
        # a version segment anywhere in the path counts (Gemini's compat endpoint ends /v1beta/openai)
        ("https://generativelanguage.googleapis.com/v1beta/openai",
         "https://generativelanguage.googleapis.com/v1beta/openai"),
        # a version-looking HOSTNAME is not a path version
        ("https://v2.example.com", "https://v2.example.com/v1"),
        # Azure deployment URLs carry their own path + api-version — never rewritten
        ("https://x.openai.azure.com/openai/deployments/gpt4o/chat/completions?api-version=2024-02-01",
         "https://x.openai.azure.com/openai/deployments/gpt4o/chat/completions?api-version=2024-02-01"),
    ],
)
def test_normalize_base_url(raw: str, expected: str) -> None:
    assert normalize_base_url(raw) == expected


def test_client_normalizes_and_is_idempotent() -> None:
    """The client stores the normalised base, and normalising it again is a no-op."""
    c = LLMClient("openai", "gpt-4o-mini", "https://api.openai.com", "sk-test")
    assert c.base_url == "https://api.openai.com/v1"
    assert normalize_base_url(c.base_url) == c.base_url


def test_404_error_names_the_url_and_model() -> None:
    """A 404 used to say only 'openai HTTP 404' — useless for finding a wrong base URL."""
    c = LLMClient("openai", "some-model", "https://gw.example/v1", "sk-test")
    msg = c._http_error(404, '{"error":"Invalid request"}', "https://gw.example/v1/chat/completions")
    assert "https://gw.example/v1/chat/completions" in msg
    assert "some-model" in msg
