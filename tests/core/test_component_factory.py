import pytest
from core.notifications.formatters.component_factory import (
    build_header, build_fact_set, wrap_card
)

# --- HAPPY PATH ---
def test_should_return_valid_header_when_data_is_correct():
    header = build_header("Título Teste", "Subtítulo Teste", color="accent")
    assert header["type"] == "Container"
    assert header["items"][0]["text"] == "Título Teste"
    assert header["style"] == "accent"

def test_should_return_valid_card_with_full_structure_when_body_and_actions_provided():
    body = [{"type": "TextBlock", "text": "Corpo"}]
    actions = [{"type": "Action.OpenUrl", "title": "Link", "url": "http://test.com"}]
    card = wrap_card(body, actions)
    assert card["type"] == "AdaptiveCard"
    assert card["body"] == body
    assert card["actions"] == actions

# --- EDGE CASES ---
def test_should_handle_empty_strings_in_header_gracefully():
    header = build_header("", "")
    assert header["items"][0]["text"] == ""
    assert header["items"][1]["text"] == ""

def test_should_render_empty_fact_set_when_list_is_empty():
    fact_set = build_fact_set([])
    assert fact_set["facts"] == []

def test_should_handle_special_characters_in_markdown():
    # O componente deve aceitar markdown sem quebrar o JSON
    title = "CVE-2026-1234 **CRITICAL**"
    header = build_header(title, "Sub")
    assert title in header["items"][0]["text"]

# --- ERRORS & MALFORMED DATA ---
def test_should_raise_error_when_passing_non_iterable_to_fact_set():
    with pytest.raises(TypeError):
        build_fact_set(None)

def test_should_fail_when_passing_invalid_structure_to_wrap_card():
    # Adaptive Cards exigem lista no body. Passar um dicionário isolado 
    # não deve quebrar a função, mas o card resultante será tecnicamente inválido para o Teams.
    card = wrap_card({"not": "a list"})
    assert isinstance(card["body"], dict)
