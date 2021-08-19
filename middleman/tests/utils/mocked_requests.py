import json
from unittest.mock import Mock


def mock_api_requests(status_code):
    def mocked(*args, **kwargs):
        class MockResponse:
            def __init__(self):
                self.status_code = status_code

            def json(self):
                response_dict = dict(body="Request Successful")
                return json.loads(response_dict)

        return MockResponse()

    return mocked
