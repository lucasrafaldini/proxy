def mock_api_requests(status_code):
    """side_effect for patching requests.head/get with a minimal fake response."""

    def mocked(*args, **kwargs):
        class MockResponse:
            def __init__(self):
                self.status_code = status_code
                self.headers = {}

            def json(self):
                return {"body": "Request Successful"}

        return MockResponse()

    return mocked
