"""A real SCIM filter parser (RFC 7644 section 3.4.2.2).

Most sample implementations regex out `userName eq "x"` and stop there, which
works right up until a provisioning connector sends anything else and then
fails in a way that is very hard to read from the other side. This is a proper
tokeniser and recursive-descent parser producing a SQLAlchemy expression, so
`and`, `or`, `not`, grouping, and the full operator set behave as specified.

Supported:
    eq ne co sw ew gt ge lt le pr
    and or not, parentheses
Not supported (deliberately):
    complex value filters on multi-valued attributes, e.g.
    emails[type eq "work"].value — the data model here stores one email per
    user, so there is nothing for the inner filter to select over. Requests
    using them get a 400 naming the unsupported construct rather than a
    silently wrong result set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Boolean, and_, func, not_, or_
from sqlalchemy.sql.elements import ColumnElement


class ScimFilterError(ValueError):
    """Raised for anything we cannot faithfully evaluate."""


# --- tokenising --------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
      (?P<space>\s+)
    | (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<string>"(?:[^"\\]|\\.)*")
    | (?P<word>[A-Za-z0-9_.:$\-]+)
    | (?P<bracket>\[)
    """,
    re.VERBOSE,
)

_LOGICAL = {"and", "or", "not"}
_COMPARISON = {"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}
_PRESENCE = {"pr"}


@dataclass
class Token:
    kind: str
    value: str


def tokenize(expression: str) -> list[Token]:
    tokens: list[Token] = []
    position = 0
    length = len(expression)

    while position < length:
        match = _TOKEN_RE.match(expression, position)
        if match is None:
            raise ScimFilterError(
                f"Unparseable character {expression[position]!r} at position {position}."
            )
        position = match.end()
        kind = match.lastgroup or ""

        if kind == "space":
            continue
        if kind == "bracket":
            raise ScimFilterError(
                "Complex attribute filters (attribute[...]) are not supported by "
                "this implementation."
            )
        if kind == "string":
            raw = match.group()[1:-1]
            tokens.append(Token("value", raw.replace('\\"', '"').replace("\\\\", "\\")))
        elif kind == "lparen":
            tokens.append(Token("lparen", "("))
        elif kind == "rparen":
            tokens.append(Token("rparen", ")"))
        else:
            word = match.group()
            lowered = word.lower()
            if lowered in _LOGICAL:
                tokens.append(Token(lowered, lowered))
            elif lowered in _COMPARISON or lowered in _PRESENCE:
                tokens.append(Token("op", lowered))
            elif lowered in ("true", "false", "null"):
                tokens.append(Token("value", lowered))
            else:
                tokens.append(Token("attr", word))
    return tokens


# --- attribute mapping -------------------------------------------------------


@dataclass
class AttributeMap:
    """Maps SCIM attribute paths onto ORM columns.

    Attribute names are case-insensitive per the specification, so lookups are
    normalised to lower case.
    """

    columns: dict[str, Any]

    def resolve(self, path: str) -> Any:
        column = self.columns.get(path.lower())
        if column is None:
            raise ScimFilterError(
                f"Unknown or unsupported filter attribute '{path}'. "
                f"Supported: {', '.join(sorted(self.columns))}."
            )
        return column


# --- parsing -----------------------------------------------------------------


class Parser:
    def __init__(self, tokens: list[Token], attributes: AttributeMap):
        self.tokens = tokens
        self.position = 0
        self.attributes = attributes

    def peek(self) -> Token | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def next(self) -> Token:
        token = self.peek()
        if token is None:
            raise ScimFilterError("Unexpected end of filter expression.")
        self.position += 1
        return token

    def parse(self) -> ColumnElement[Boolean]:
        expression = self.parse_or()
        if self.peek() is not None:
            raise ScimFilterError(
                f"Unexpected trailing token {self.peek().value!r} in filter."  # type: ignore[union-attr]
            )
        return expression

    def parse_or(self) -> ColumnElement[Boolean]:
        left = self.parse_and()
        while (token := self.peek()) and token.kind == "or":
            self.next()
            left = or_(left, self.parse_and())
        return left

    def parse_and(self) -> ColumnElement[Boolean]:
        left = self.parse_unary()
        while (token := self.peek()) and token.kind == "and":
            self.next()
            left = and_(left, self.parse_unary())
        return left

    def parse_unary(self) -> ColumnElement[Boolean]:
        token = self.peek()
        if token and token.kind == "not":
            self.next()
            following = self.peek()
            if following is None or following.kind != "lparen":
                raise ScimFilterError("'not' must be followed by a parenthesised group.")
            return not_(self.parse_unary())
        if token and token.kind == "lparen":
            self.next()
            inner = self.parse_or()
            closing = self.peek()
            if closing is None or closing.kind != "rparen":
                raise ScimFilterError("Unbalanced parentheses in filter.")
            self.next()
            return inner
        return self.parse_comparison()

    def parse_comparison(self) -> ColumnElement[Boolean]:
        attribute_token = self.next()
        if attribute_token.kind != "attr":
            raise ScimFilterError(
                f"Expected an attribute name but found {attribute_token.value!r}."
            )
        column = self.attributes.resolve(attribute_token.value)

        operator_token = self.next()
        if operator_token.kind != "op":
            raise ScimFilterError(
                f"Expected a comparison operator after '{attribute_token.value}' "
                f"but found {operator_token.value!r}."
            )
        operator = operator_token.value

        if operator == "pr":
            # "present": non-null and, for text columns, non-empty.
            if isinstance(column.type, Boolean):
                return column.isnot(None)
            return and_(column.isnot(None), column != "")

        value_token = self.next()
        if value_token.kind not in ("value", "attr"):
            raise ScimFilterError(f"Expected a value after '{operator}'.")
        return self._compare(column, operator, value_token.value)

    @staticmethod
    def _compare(column: Any, operator: str, raw_value: str) -> ColumnElement[Boolean]:
        if isinstance(column.type, Boolean):
            if operator not in ("eq", "ne"):
                raise ScimFilterError(
                    f"Operator '{operator}' cannot be applied to a boolean attribute."
                )
            truthy = raw_value.strip().lower() in ("true", "1")
            return column.is_(truthy) if operator == "eq" else column.isnot(truthy)

        # Escape LIKE wildcards so a literal % or _ in a username is matched
        # literally rather than acting as a pattern.
        escaped = raw_value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        lowered_column = func.lower(column)
        lowered_value = raw_value.lower()

        if operator == "eq":
            return lowered_column == lowered_value
        if operator == "ne":
            return lowered_column != lowered_value
        if operator == "co":
            return lowered_column.like(f"%{escaped.lower()}%", escape="\\")
        if operator == "sw":
            return lowered_column.like(f"{escaped.lower()}%", escape="\\")
        if operator == "ew":
            return lowered_column.like(f"%{escaped.lower()}", escape="\\")
        if operator == "gt":
            return column > raw_value
        if operator == "ge":
            return column >= raw_value
        if operator == "lt":
            return column < raw_value
        if operator == "le":
            return column <= raw_value
        raise ScimFilterError(f"Unsupported operator '{operator}'.")


def build_filter(expression: str, attributes: AttributeMap) -> ColumnElement[Boolean] | None:
    """Compile a SCIM filter string into a SQLAlchemy WHERE clause."""
    expression = (expression or "").strip()
    if not expression:
        return None
    tokens = tokenize(expression)
    if not tokens:
        return None
    return Parser(tokens, attributes).parse()
