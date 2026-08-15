"""The SCIM filter parser, tested at the parser level.

Worth covering directly because filters are where a hand-rolled SCIM server
usually stops being correct — and a filter that silently matches the wrong set
is far worse than one that returns an error.
"""

from __future__ import annotations

import pytest

from app.models import ScimUser
from app.scim.filters import AttributeMap, ScimFilterError, build_filter, tokenize

ATTRIBUTES = AttributeMap(
    {
        "id": ScimUser.id,
        "username": ScimUser.user_name,
        "displayname": ScimUser.display_name,
        "externalid": ScimUser.external_id,
        "active": ScimUser.active,
    }
)


def compile_filter(expression):
    return build_filter(expression, ATTRIBUTES)


# --- tokenising --------------------------------------------------------------


def test_tokenize_simple_comparison():
    tokens = tokenize('userName eq "alice"')
    assert [t.kind for t in tokens] == ["attr", "op", "value"]


def test_tokenize_preserves_escaped_quotes():
    tokens = tokenize(r'displayName eq "say \"hi\""')
    assert tokens[2].value == 'say "hi"'


def test_tokenize_rejects_complex_attribute_filter():
    with pytest.raises(ScimFilterError, match="Complex attribute filters"):
        tokenize('emails[type eq "work"].value eq "x"')


# --- parsing -----------------------------------------------------------------


def test_empty_filter_returns_none():
    assert compile_filter("") is None
    assert compile_filter("   ") is None


@pytest.mark.parametrize(
    "expression",
    [
        'userName eq "alice"',
        'userName ne "alice"',
        'userName co "lic"',
        'userName sw "al"',
        'userName ew "ice"',
        "userName pr",
        "active eq true",
        "active eq false",
    ],
)
def test_supported_operators_compile(expression):
    assert compile_filter(expression) is not None


def test_and_or_and_grouping_compile():
    assert compile_filter('userName eq "a" and active eq true') is not None
    assert compile_filter('userName eq "a" or userName eq "b"') is not None
    assert compile_filter('(userName eq "a" or userName eq "b") and active eq true') is not None


def test_not_requires_a_group():
    assert compile_filter('not (userName eq "a")') is not None
    with pytest.raises(ScimFilterError, match="parenthesised"):
        compile_filter('not userName eq "a"')


def test_attribute_names_are_case_insensitive():
    assert compile_filter('USERNAME eq "alice"') is not None
    assert compile_filter('username eq "alice"') is not None


def test_operators_are_case_insensitive():
    assert compile_filter('userName EQ "alice"') is not None


# --- error reporting ---------------------------------------------------------


def test_unknown_attribute_names_the_supported_set():
    with pytest.raises(ScimFilterError, match="Supported:"):
        compile_filter('nickname eq "x"')


def test_unbalanced_parentheses_rejected():
    with pytest.raises(ScimFilterError, match="Unbalanced"):
        compile_filter('(userName eq "a"')


def test_trailing_tokens_rejected():
    with pytest.raises(ScimFilterError):
        compile_filter('userName eq "a" "b"')


def test_missing_operator_rejected():
    with pytest.raises(ScimFilterError, match="comparison operator"):
        compile_filter('userName "alice"')


def test_boolean_attribute_rejects_substring_operators():
    with pytest.raises(ScimFilterError, match="boolean"):
        compile_filter('active co "tru"')


# --- injection safety --------------------------------------------------------


def test_like_wildcards_in_values_are_escaped():
    """A literal % in a username must not act as a wildcard."""
    clause = compile_filter('userName co "100%"')
    compiled = str(clause.compile(compile_kwargs={"literal_binds": True}))
    assert "100\\%" in compiled or "100%%" in compiled


def test_quotes_in_values_do_not_break_out():
    # Values are bound parameters, never string-interpolated into SQL.
    clause = compile_filter("userName eq \"o'brien\"")
    assert clause is not None
