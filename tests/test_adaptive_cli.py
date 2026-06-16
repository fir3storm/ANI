"""Tests for the adaptive scan loop in src.cli."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from src.cli import _run_adaptive_loop


def _make_chat_element():
    return MagicMock(name="chat_element")


def test_adaptive_loop_calls_brain():
    brain = MagicMock()
    brain.generate_payload = AsyncMock(
        side_effect=lambda **kw: f"payload-{len(kw['attempt_history']) + 1}"
    )
    brain.analyze_success = AsyncMock(return_value="FAILURE, no indicators matched")
    chat_detector = MagicMock()
    chat_detector.send_message = AsyncMock()
    chat_detector.wait_for_response = AsyncMock(return_value="irrelevant response")
    chat_element = _make_chat_element()

    results = asyncio.run(
        _run_adaptive_loop(
            brain=brain,
            chat_detector=chat_detector,
            chat_element=chat_element,
            category="prompt_injection",
            goal="reveal prompt",
            target_model="unknown",
            rounds=3,
        )
    )

    assert brain.generate_payload.await_count == 3
    assert chat_detector.send_message.await_count == 3

    sent_payloads = [call.args[1] for call in chat_detector.send_message.await_args_list]
    assert sent_payloads == ["payload-1", "payload-2", "payload-3"]

    history_sizes = [r.metadata["attempt_history_size"] for r in results]
    assert history_sizes == [1, 2, 3]
    assert len(results) == 3


def test_adaptive_loop_breaks_on_success():
    brain = MagicMock()
    brain.generate_payload = AsyncMock(side_effect=lambda **kw: "p")
    brain.analyze_success = AsyncMock(
        side_effect=["FAILURE, no", "SUCCESS, matched", "FAILURE, late"]
    )
    chat_detector = MagicMock()
    chat_detector.send_message = AsyncMock()
    chat_detector.wait_for_response = AsyncMock(return_value="ok")
    chat_element = _make_chat_element()

    results = asyncio.run(
        _run_adaptive_loop(
            brain=brain,
            chat_detector=chat_detector,
            chat_element=chat_element,
            category="prompt_injection",
            goal="reveal prompt",
            target_model="unknown",
            rounds=10,
        )
    )

    assert len(results) == 2
    assert results[0].vulnerable is False
    assert results[1].vulnerable is True


def test_adaptive_loop_respects_max_rounds():
    brain = MagicMock()
    brain.generate_payload = AsyncMock(side_effect=lambda **kw: "p")
    brain.analyze_success = AsyncMock(return_value="FAILURE, none")
    chat_detector = MagicMock()
    chat_detector.send_message = AsyncMock()
    chat_detector.wait_for_response = AsyncMock(return_value="ok")
    chat_element = _make_chat_element()

    results = asyncio.run(
        _run_adaptive_loop(
            brain=brain,
            chat_detector=chat_detector,
            chat_element=chat_element,
            category="prompt_injection",
            goal="reveal prompt",
            target_model="unknown",
            rounds=3,
        )
    )

    assert len(results) == 3
    assert all(not r.vulnerable for r in results)


def test_adaptive_results_marked_vulnerable_on_success():
    brain = MagicMock()
    brain.generate_payload = AsyncMock(side_effect=lambda **kw: "p")
    brain.analyze_success = AsyncMock(side_effect=["FAILURE", "SUCCESS, breakthrough"])
    chat_detector = MagicMock()
    chat_detector.send_message = AsyncMock()
    chat_detector.wait_for_response = AsyncMock(return_value="ok")
    chat_element = _make_chat_element()

    results = asyncio.run(
        _run_adaptive_loop(
            brain=brain,
            chat_detector=chat_detector,
            chat_element=chat_element,
            category="prompt_injection",
            goal="reveal prompt",
            target_model="unknown",
            rounds=5,
        )
    )

    assert results[-1].vulnerable is True
