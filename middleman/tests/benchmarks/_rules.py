"""Rule fixtures shared by the benchmarks (no pytest collection: leading underscore)."""

from middleman.models import BlacklistRule
from middleman.rules import CLIENT_RULE_TYPES
from middleman.ruleset import RuleSet, compile_client_rule

CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
HOSTILE_UA = "a" * 8192 + "!"  # about the largest header a server accepts
CLIENT = ("192.168.1.10", "home/")  # matches none of the generated rules


def rule_values(count):
    """count/4 rules of each client type, none matching CLIENT or CHROME."""
    values = []
    for i in range(count // 4):
        values += [
            ("ip", "10.{}.{}.0/24".format(i // 256, i % 256)),
            ("path", "blocked{}/*".format(i)),
            ("user_agent", "badbot{}".format(i)),
            ("user_agent_re", r"scanner{}/\d+".format(i)),
        ]
    return values


def regex_heavy_values(count):
    """Only User-Agent regexes: the worst case for per-rule matching."""
    return [("user_agent_re", r"(a+)+scanner{}|evil{}bot/\d+".format(i, i)) for i in range(count)]


def store(values):
    BlacklistRule.objects.bulk_create(BlacklistRule(rule_type=t, value=v) for t, v in values)


def compiled(values, use_prefilter=True):
    """RuleSet in database order (rule_type, value), as the cache would build it."""
    ordered = sorted(values)
    assert all(t in CLIENT_RULE_TYPES for t, _ in ordered)
    return RuleSet([compile_client_rule(t, v) for t, v in ordered], use_prefilter=use_prefilter)
