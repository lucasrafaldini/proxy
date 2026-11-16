"""
Client ``User-Agent`` matching for ``user_agent`` / ``user_agent_re`` blacklist rules.

The User-Agent header is written by the client, so these rules stop
well-behaved bots, scanners and scripts that announce themselves (``sqlmap``,
``python-requests``, an abusive crawler...), not a determined attacker, who
can send any value. Use them next to ``ip`` rules and the rate limit, never
instead of them. For the same reason the User-Agent is *not* part of the
rate-limit key: rotating it must not give a client a fresh limit.

Rule syntax:

``user_agent``
    Case-insensitive **substring**: ``sqlmap`` blocks ``sqlmap/1.7.2#stable``
    and ``Mozilla/5.0 (compatible; SQLMap)``. At least
    ``MIN_USER_AGENT_LENGTH`` characters, ASCII, no ``*`` (it is not a
    wildcard here; use a regex rule for patterns). Never matches a request
    without a User-Agent.
``user_agent_re``
    RE2 regex, case-insensitive, **searched** anywhere in the User-Agent
    (anchor with ``^`` / ``$``). ``^$`` blocks requests with a missing or
    empty User-Agent. Same engine and limits as ``host_re``.

A missing header and an empty header are the same thing (``""``). Servers
join repeated User-Agent headers into one value, which is matched as a whole.
"""

from typing import NamedTuple

from middleman.destinations import MAX_REGEX_LENGTH, compile_rule_regex
from middleman.exceptions import InvalidRuleError

RULE_TYPE_USER_AGENT = "user_agent"
RULE_TYPE_USER_AGENT_RE = "user_agent_re"

# Shorter substrings ("go", "a", "/") match unrelated User-Agents by accident.
MIN_USER_AGENT_LENGTH = 3
# Only this much of the (client-controlled) User-Agent goes into log lines.
LOGGED_USER_AGENT_LENGTH = 200

# User-Agents used to detect regexes that would block every client that sends
# one. A missing User-Agent ("") is deliberately not a probe: "^$" is a valid
# rule, and "." (anything non-empty) must still be caught.
_MATCH_ALL_PROBES = (
    "x",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "okhttp/4.12.0",
)


class UserAgentRule(NamedTuple):
    kind: str  # "substring" | "regex"
    target: object  # lowercase str | compiled RE2 pattern


def _invalid(reason: str, message: str, value: str, rule_type: str) -> InvalidRuleError:
    return InvalidRuleError(reason, message, rule_type=rule_type, value=value)


def _has_control_characters(text: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in text)


def parse_user_agent_rule(value: str) -> UserAgentRule:
    """Parse a ``user_agent`` (substring) rule. Raises ``InvalidRuleError``."""
    rule_type = RULE_TYPE_USER_AGENT
    raw = (value or "").strip()
    if not raw:
        raise _invalid("empty", "User-Agent rule cannot be empty.", value, rule_type)
    if _has_control_characters(raw):
        raise _invalid(
            "invalid_characters",
            "User-Agent rules cannot contain control characters (tabs, line breaks...); "
            "they never appear in a User-Agent header.",
            value, rule_type,
        )
    if not raw.isascii():
        raise _invalid(
            "non_ascii",
            "User-Agent rules must be ASCII: non-ASCII bytes in headers do not reach the "
            "proxy as the characters you typed, so the rule would never match.",
            value, rule_type,
        )
    if len(raw) < MIN_USER_AGENT_LENGTH:
        raise _invalid(
            "too_short",
            "'{}' is too short: User-Agent rules match any part of the header, so rules "
            "under {} characters block unrelated clients. Use a distinctive token such as "
            "sqlmap or python-requests/.".format(raw, MIN_USER_AGENT_LENGTH),
            value, rule_type,
        )
    if "*" in raw:
        raise _invalid(
            "unsupported_wildcard",
            "User-Agent rules already match any part of the header and '*' is not a "
            "wildcard here; remove it, or choose the 'User-Agent (regex)' rule type for patterns.",
            value, rule_type,
        )
    return UserAgentRule("substring", raw.lower())


def parse_user_agent_regex(value: str) -> UserAgentRule:
    """
    Parse and lint a ``user_agent_re`` rule. Raises ``InvalidRuleError``.

    Unlike ``host_re`` there is no dot lint: '.' matching any character in a
    version number (``curl/7.1``) only widens the match slightly, and spaces,
    '/' and '@' are normal in User-Agents.
    """
    rule_type = RULE_TYPE_USER_AGENT_RE
    pattern = (value or "").strip()
    if not pattern:
        raise _invalid("empty", "Regex rule cannot be empty.", value, rule_type)
    if pattern[:3].lower() == "re:":
        raise _invalid(
            "regex_prefix",
            "Enter the pattern without the 're:' prefix; the rule type already says it is a regex.",
            value, rule_type,
        )
    if len(pattern) > MAX_REGEX_LENGTH:
        raise _invalid(
            "regex_too_long",
            "Regex is {} characters long; the maximum is {}.".format(len(pattern), MAX_REGEX_LENGTH),
            value, rule_type,
        )
    if not pattern.isascii():
        raise _invalid(
            "regex_non_ascii",
            "Regex must be ASCII: non-ASCII bytes in headers do not reach the proxy as "
            "the characters you typed (use \\xNN escapes if you really need them).",
            value, rule_type,
        )
    compiled = compile_rule_regex(pattern, value, rule_type)
    if all(compiled.search(probe) for probe in _MATCH_ALL_PROBES):
        raise _invalid(
            "regex_matches_everything",
            "Regex matches every User-Agent, which would block all clients; make it "
            "specific (e.g. sqlmap|nikto, or ^$ for a missing User-Agent).",
            value, rule_type,
        )
    return UserAgentRule("regex", compiled)


def user_agent_matches(rule: UserAgentRule, user_agent: str) -> bool:
    """True if ``user_agent`` ("" when missing) is matched by ``rule``."""
    user_agent = user_agent or ""
    if rule.kind == "substring":
        return rule.target in user_agent.lower()
    if rule.kind == "regex":
        return rule.target.search(user_agent) is not None
    return False


def user_agent_from_meta(meta) -> str:
    """The request's User-Agent, or "" when the header is missing."""
    return meta.get("HTTP_USER_AGENT", "") or ""


def loggable_user_agent(user_agent: str) -> str:
    """The User-Agent truncated for log lines (log with %r so it cannot forge lines)."""
    user_agent = user_agent or ""
    if len(user_agent) <= LOGGED_USER_AGENT_LENGTH:
        return user_agent
    return "{}…(+{} chars)".format(
        user_agent[:LOGGED_USER_AGENT_LENGTH], len(user_agent) - LOGGED_USER_AGENT_LENGTH
    )
