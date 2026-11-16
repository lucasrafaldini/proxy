import re

POLICY_BLOCK_BODY = re.compile(
    rb"Forbidden: the request was blocked by the proxy's access policy \(ref ([0-9a-f]{12})\)\."
)


def assert_policy_block(testcase, response, log_output=None, hidden=()):
    """
    ``response`` is the generic policy 403: fixed text plus a reference, which
    is also in the log line (when ``log_output`` is given). None of ``hidden``
    (rule values, hosts, the client's User-Agent...) may appear in the body.
    Returns the reference.
    """
    testcase.assertEqual(response.status_code, 403)
    testcase.assertEqual(response["Content-Type"], "text/plain; charset=utf-8")
    match = POLICY_BLOCK_BODY.fullmatch(response.content)
    testcase.assertIsNotNone(match, response.content)
    ref = match.group(1).decode()
    for secret in hidden:
        testcase.assertNotIn(secret.encode() if isinstance(secret, str) else secret, response.content)
    if log_output is not None:
        testcase.assertTrue(any("ref={}".format(ref) in line for line in log_output), log_output)
    return ref
