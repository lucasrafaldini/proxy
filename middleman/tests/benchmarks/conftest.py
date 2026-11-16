def pytest_terminal_summary(terminalreporter):
    """After pytest-benchmark's tables: the throughput table and the decisions table."""
    import sys

    module = sys.modules.get("bench_throughput")
    throughput_results = getattr(module, "RESULTS", {}) if module else {}
    lines = module.summary_lines() if module else []
    if lines:
        terminalreporter.write_sep("-", "throughput")
        for line in lines:
            terminalreporter.write_line(line)

    session = getattr(terminalreporter.config, "_benchmarksession", None)
    benchmarks = getattr(session, "benchmarks", None) or []
    medians = {}
    for benchmark in benchmarks:
        median = getattr(getattr(benchmark, "stats", None), "median", None)
        if median:
            medians[benchmark.name] = median
    from _decisions import decision_rows, format_table

    table = format_table(decision_rows(medians, throughput_results))
    if table:
        terminalreporter.write_sep("-", "decisions")
        for line in table:
            terminalreporter.write_line(line)
