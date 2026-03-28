"""
_toon_encoder.py — Token-Oriented Object Notation (TOON) encoder.

The published toon_format package ships with encode() stubbed out as
NotImplementedError. This module provides a complete implementation that
follows the format rules shown in the toon_format package documentation.

TOON format rules
-----------------
  Scalar field          key: value
  Primitive list        key[N]: v1,v2,...
  Homogeneous obj list  key[N]{f1,f2}:        (tabular — all values primitive)
                          v1,v2
                          v1,v2
  Nested object         key:
                          subkey: value
  Top-level list        [N]: v1,v2,...
  Top-level obj list    [N]{f1,f2}:
                          v1,v2
"""

from __future__ import annotations

from typing import Any


# Two spaces per indentation level — matches toon_format's default indent.
_INDENT = "  "


def encode(value: Any) -> str:
    """
    Encode a JSON-serialisable Python value to TOON format.

    Entry point for callers. Delegates to _encode_value at level 0.

    Args:
        value: Any JSON-serialisable value (dict, list, or primitive).

    Returns:
        A TOON-formatted string with no trailing newline or spaces.
    """
    return _encode_value(value, level=0)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_primitive(value: Any) -> bool:
    """Return True for scalar JSON types (str, int, float, bool, None)."""
    return value is None or isinstance(value, (bool, int, float, str))


def _scalar_str(value: Any) -> str:
    """
    Convert a primitive to its TOON literal representation.

    None → 'null', booleans → lowercase 'true'/'false', all others → str().
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _shared_keys(items: list[dict]) -> list[str] | None:
    """
    Return the common key list when every item shares identical keys.

    Returns None if the list is empty, if any item is not a dict, or if
    the key sets differ between items.
    """
    if not items or not all(isinstance(item, dict) for item in items):
        return None
    first_keys = list(items[0].keys())
    if all(list(item.keys()) == first_keys for item in items):
        return first_keys
    return None


def _all_values_primitive(items: list[dict], keys: list[str]) -> bool:
    """
    Return True when every cell in the table is a primitive.

    Tabular encoding is only safe when rows contain no nested structures,
    because commas are used as column separators.
    """
    return all(
        _is_primitive(item[k])
        for item in items
        for k in keys
    )


# ---------------------------------------------------------------------------
# Core recursive encoder
# ---------------------------------------------------------------------------

def _encode_value(value: Any, level: int) -> str:
    """
    Recursively encode any value at the given indentation level.

    Dispatches to the appropriate sub-encoder based on type.
    """
    if _is_primitive(value):
        return _scalar_str(value)
    if isinstance(value, dict):
        return _encode_object(value, level)
    if isinstance(value, list):
        return _encode_bare_list(value, level)
    # Non-JSON types (e.g. sets, custom objects) fall back to str().
    return _scalar_str(str(value))


def _encode_object(obj: dict, level: int) -> str:
    """
    Encode a dict as a block of key: value lines at the given level.

    Each key-value pair is delegated to _encode_entry, which handles
    the three sub-cases: scalar, nested object, and list.
    """
    if not obj:
        return _INDENT * level + "{}"
    lines = [_encode_entry(k, v, level) for k, v in obj.items()]
    return "\n".join(lines)


def _encode_entry(key: str, value: Any, level: int) -> str:
    """
    Encode one key-value pair within an object at the given level.

    Scalar    → 'indent key: value'
    Dict      → 'indent key:\n  <nested>'
    List      → delegated to _encode_key_list
    """
    indent = _INDENT * level

    if _is_primitive(value):
        return f"{indent}{key}: {_scalar_str(value)}"

    if isinstance(value, dict):
        if not value:
            return f"{indent}{key}: {{}}"
        nested = _encode_object(value, level + 1)
        return f"{indent}{key}:\n{nested}"

    if isinstance(value, list):
        return _encode_key_list(key, value, level)

    # Fallback for non-standard types.
    return f"{indent}{key}: {_scalar_str(str(value))}"


def _encode_key_list(key: str, items: list, level: int) -> str:
    """
    Encode a key whose value is a list.

    Three cases are handled in order of preference:

    1. Empty list          → 'key[0]:'
    2. All primitives      → 'key[N]: v1,v2,...'   (inline)
    3. Homogeneous dicts
       with primitive vals → 'key[N]{f1,f2}:\n  r1\n  r2'  (tabular)
    4. Everything else     → 'key[N]:\n  item\n  item'     (block)
    """
    indent = _INDENT * level
    n = len(items)

    if n == 0:
        return f"{indent}{key}[0]:"

    # Case 2 — inline primitive list.
    if all(_is_primitive(item) for item in items):
        values = ",".join(_scalar_str(v) for v in items)
        return f"{indent}{key}[{n}]: {values}"

    # Case 3 — tabular homogeneous dicts.
    keys = _shared_keys(items)
    if keys is not None and _all_values_primitive(items, keys):
        header = ",".join(keys)
        row_indent = _INDENT * (level + 1)
        rows = "\n".join(
            f"{row_indent}" + ",".join(_scalar_str(item[k]) for k in keys)
            for item in items
        )
        return f"{indent}{key}[{n}]{{{header}}}:\n{rows}"

    # Case 4 — block list (mixed or complex items).
    # _encode_value already adds the correct indentation for dicts and
    # nested lists. For primitives there is no built-in indent, so we
    # prepend it explicitly.
    row_indent = _INDENT * (level + 1)
    rows = "\n".join(
        f"{row_indent}{_scalar_str(item)}" if _is_primitive(item)
        else _encode_value(item, level + 1)
        for item in items
    )
    return f"{indent}{key}[{n}]:\n{rows}"


def _encode_bare_list(items: list, level: int) -> str:
    """
    Encode a top-level list (not attached to a key).

    Mirrors _encode_key_list but uses '[N]' as the key placeholder.
    """
    indent = _INDENT * level
    n = len(items)

    if n == 0:
        return f"{indent}[0]:"

    if all(_is_primitive(item) for item in items):
        values = ",".join(_scalar_str(v) for v in items)
        return f"{indent}[{n}]: {values}"

    keys = _shared_keys(items)
    if keys is not None and _all_values_primitive(items, keys):
        header = ",".join(keys)
        row_indent = _INDENT * (level + 1)
        rows = "\n".join(
            f"{row_indent}" + ",".join(_scalar_str(item[k]) for k in keys)
            for item in items
        )
        return f"{indent}[{n}]{{{header}}}:\n{rows}"

    row_indent = _INDENT * (level + 1)
    rows = "\n".join(
        f"{row_indent}{_scalar_str(item)}" if _is_primitive(item)
        else _encode_value(item, level + 1)
        for item in items
    )
    return f"{indent}[{n}]:\n{rows}"
