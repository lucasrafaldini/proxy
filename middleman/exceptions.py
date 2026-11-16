class ServerNotRespondingException(Exception):
    """
    Exception raised when the requested server is not responding.
    """

    def __init__(self, url):
        self.url = url

    def __str__(self):
        return "Url '%s' is not responding." % self.url


class ExceededRequestsLimitException(Exception):
    """
    Exception raised when the number of requests has exceeded the
    allowed limit.
    """

    def __init__(self, ip, path):
        self.ip = ip
        self.path = path

    def __str__(self):
        return "Address {} has exceeded the allowed requests limit for path {}".format(
            self.ip, self.path
        )


class AccessNotRegisteredException(Exception):
    """
    Exception raised when the request is not registered.
    """

    def __init__(self, key, ip, path):
        self.key = key
        self.ip = ip
        self.path = path

    def __str__(self):
        return "Request from {} could not be registered for path {} - Key: {}".format(
            self.ip, self.path, self.key
        )


class BlacklistedAccessException(Exception):
    """
    Exception raised when the request matches a blacklist rule.
    """

    def __init__(self, ip, path, rule_type, rule_value, user_agent=None):
        self.ip = ip
        self.path = path
        self.rule_type = rule_type
        self.rule_value = rule_value
        # The client's User-Agent, set only when a User-Agent rule matched.
        self.user_agent = user_agent

    def __str__(self):
        return "Access from {} to {} blocked by {} rule: {}".format(
            self.ip, self.path, self.rule_type, self.rule_value
        )


class BlockedDestinationException(BlacklistedAccessException):
    """
    Exception raised when the proxy would reach a destination host (the target
    itself or a redirect hop) that matches a ``host`` blacklist rule.
    """

    def __init__(self, host, rule_value, ip=None, path=None):
        super().__init__(ip, path, "host", rule_value)
        self.host = host

    def __str__(self):
        return "Access to {} blocked by host rule: {}".format(self.host, self.rule_value)


class UpstreamTimeoutException(ServerNotRespondingException):
    """The target did not answer within the timeout (mapped to 504)."""

    def __str__(self):
        return "Url '%s' timed out." % self.url


class UpstreamStatusException(Exception):
    """
    The target answered the availability check (HEAD) with a non-200 status,
    so the proxy did not fetch the content (mapped to 502).
    """

    def __init__(self, url, status_code):
        self.url = url
        self.status_code = status_code

    def __str__(self):
        return "Url '{}' answered the availability check with {}.".format(
            self.url, self.status_code
        )


class DestinationUnverifiableException(Exception):
    """
    An IP/CIDR host rule needs the destination's addresses but its name could
    not be resolved. The proxy refuses to connect instead of skipping the rule
    (fail closed; mapped to 502).
    """

    def __init__(self, host, rule_value):
        self.host = host
        self.rule_value = rule_value

    def __str__(self):
        return "Cannot verify destination {} against host rule {}: name does not resolve.".format(
            self.host, self.rule_value
        )


class InvalidRuleError(ValueError):
    """
    A blacklist rule value is malformed or likely a human error.

    ``reason`` is a stable, machine-readable code (e.g. ``regex_syntax``,
    ``regex_unescaped_dot``) used in logs and tests; ``str(exc)`` is the
    human-readable explanation shown to the admin.
    """

    def __init__(self, reason, message, rule_type=None, value=None):
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.rule_type = rule_type
        self.value = value

    def __str__(self):
        return self.message


class ClientAddressUnavailableException(Exception):
    """The request has no usable REMOTE_ADDR, so the client cannot be identified (400)."""

    def __init__(self, remote_addr):
        self.remote_addr = remote_addr

    def __str__(self):
        return "Cannot determine the client address (REMOTE_ADDR={!r}).".format(self.remote_addr)
