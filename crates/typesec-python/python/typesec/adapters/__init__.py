"""Per-SDK adapter helpers.

Each module is a thin, dependency-free veneer over :func:`typesec.guard` with
the dialect fixed and the denial payloads shaped for that SDK's message
history. Only :mod:`typesec.adapters.pydantic_ai` offers SDK-specific hooks
(a ``prepare_tools`` filter) — and even that imports nothing from Pydantic AI.
"""
