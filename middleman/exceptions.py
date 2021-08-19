class ServerNotRespondingException(BaseException):
    """
    Exception raised when the requested server is not responding.
    """

    def __init__(self, url):
        self.url = url

    def __str__(self):
        return "Url '%s' is not responding." % self.url


class ExceededRequestsLimitException(BaseException):
    """
    Exception raised when the number of requests has exceeded the
    allowed limit.
    """

    def __init__(self, ip, url):
        self.ip = ip
        self.url = url

    def __str__(self):
        return "Address {} has exceeded the allowed requests limit for path {}".format(
            self.ip, self.path
        )


class AccessNotRegisteredException(BaseException):
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
