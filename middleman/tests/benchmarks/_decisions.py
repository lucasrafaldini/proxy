"""
The "decisions" table printed after a benchmark run: for every design
decision, the adopted flow next to its alternative and the measured gain or
loss, so each choice can be judged (and challenged) with numbers from the
same run. Rows whose benchmarks were not part of the run are simply omitted.
"""

from typing import List, NamedTuple, Optional


class Decision(NamedTuple):
    title: str
    adopted: str  # benchmark name (time) or throughput key (requests/s)
    alternative: str
    adopted_label: str
    alternative_label: str


# Latency benchmarks: values are seconds per operation (lower is better).
TIME_DECISIONS = [
    Decision("Compiled rule-set cache (blacklist check, 100 rules)",
             "after[ 100 rules]", "before[ 100 rules]", "compiled + token", "load + re-validate"),
    Decision("Compiled rule-set cache (blacklist check, 400 rules)",
             "after[ 400 rules]", "before[ 400 rules]", "compiled + token", "load + re-validate"),
    Decision("Compiled rule-set cache (blacklist check, 2000 rules)",
             "after[2000 rules]", "before[2000 rules]", "compiled + token", "load + re-validate"),
    Decision("User-Agent prefilter (matching only, 400 rules)",
             "match-only[ 400 rules, prefilter]", "match-only[ 400 rules, no prefilter]",
             "prefilter", "rule-by-rule"),
    Decision("User-Agent prefilter (matching only, 2000 rules)",
             "match-only[2000 rules, prefilter]", "match-only[2000 rules, no prefilter]",
             "prefilter", "rule-by-rule"),
    Decision("User-Agent prefilter (worst case: 8 KB UA, 400 regexes)",
             "sequential[worst-400-regex-8KB-prefilter]", "sequential[worst-400-regex-8KB]",
             "prefilter", "rule-by-rule"),
    Decision("In-request parallelism (blacklist, 2000 rules): threads",
             "sequential[typical-2000]", "threads-4[typical-2000]", "sequential", "4 threads"),
    Decision("In-request parallelism (blacklist, 2000 rules): processes",
             "sequential[typical-2000]", "processes-4[typical-2000]", "sequential", "4 processes"),
    Decision("In-request parallelism (blacklist, 2000 rules): asyncio",
             "sequential[typical-2000]", "asyncio-gather[typical-2000]", "sequential", "asyncio gather"),
    Decision("In-request parallelism (worst case UA): threads",
             "sequential[worst-400-regex-8KB]", "threads-4[worst-400-regex-8KB]", "sequential", "4 threads"),
    Decision("In-request parallelism (worst case UA): processes",
             "sequential[worst-400-regex-8KB]", "processes-4[worst-400-regex-8KB]", "sequential", "4 processes"),
    Decision("Upstream keep-alive pool (whole request, real upstream)",
             "request[keep-alive pool]", "request[new connections (before)]",
             "keep-alive pool", "new connections"),
]

# Throughput benchmarks: values are requests/second (higher is better);
# keys are (mode, clients) from bench_throughput.RESULTS.
THROUGHPUT_DECISIONS = [
    Decision("Concurrency across requests (16 clients): threads",
             "('threaded', 16)", "('single-threaded', 16)", "threaded server", "single-threaded"),
    Decision("Concurrency across requests (16 clients): processes",
             "('threaded x4 procs', 16)", "('threaded', 16)", "4 processes", "1 process"),
    Decision("Upstream keep-alive at saturation (16 clients, 4 processes)",
             "('threaded x4 procs', 16)", "('x4 procs, no keepalive', 16)", "keep-alive", "new connections"),
]


def _format_seconds(value: float) -> str:
    for unit, factor in (("s", 1.0), ("ms", 1e-3), ("us", 1e-6)):
        if value >= factor:
            return "{:.3g} {}".format(value / factor, unit)
    return "{:.3g} ns".format(value / 1e-9)


def _verdict(gain: float) -> str:
    """How the adopted flow compares: 'Nx faster', 'Nx slower' or '~even'."""
    if gain >= 1.05:
        return "{:.2f}x faster".format(gain)
    if gain <= 1 / 1.05:
        return "{:.2f}x slower".format(1 / gain)
    return "~even ({:.2f}x)".format(gain)


def _row(decision, adopted_value, alternative_value, gain):
    return (decision.title,
            "{} = {}".format(decision.adopted_label, adopted_value),
            "{} = {}".format(decision.alternative_label, alternative_value),
            _verdict(gain))


def decision_rows(medians_by_name: dict, throughput: Optional[dict] = None) -> List[tuple]:
    """
    Rows (title, adopted, alternative, verdict). ``medians_by_name`` maps
    benchmark names to median seconds; ``throughput`` maps (mode, clients)
    to requests/second.
    """
    rows = []
    for decision in TIME_DECISIONS:
        adopted, alternative = medians_by_name.get(decision.adopted), medians_by_name.get(decision.alternative)
        if adopted and alternative:
            rows.append(_row(decision, _format_seconds(adopted), _format_seconds(alternative),
                             alternative / adopted))
    throughput = {str(key): value for key, value in (throughput or {}).items()}
    for decision in THROUGHPUT_DECISIONS:
        adopted, alternative = throughput.get(decision.adopted), throughput.get(decision.alternative)
        if adopted and alternative:
            rows.append(_row(decision, "{:.1f} req/s".format(adopted), "{:.1f} req/s".format(alternative),
                             adopted / alternative))
    return rows


def format_table(rows: List[tuple]) -> List[str]:
    if not rows:
        return []
    lines = [
        "Decisions, adopted flow vs alternative (medians of this run; >1x faster = the adopted flow wins):",
        "",
    ]
    width = max(len(row[0]) for row in rows)
    for title, adopted, alternative, verdict in rows:
        lines.append("  {:<{w}}  {:<32} vs {:<34} -> {}".format(title, adopted, alternative, verdict, w=width))
    return lines
