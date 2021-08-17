from middleman.services import ProxyManager
from utils.factories.access_entry import AccessEntryModelFactory
from exceptions import ExceededRequestsLimitException



class test_proxy_manager(unittest.TestCase):

    def setUp(self):
        self.proxy_manager = ProxyManager()

    def test_create_unique_key(self):
        access_entry = AccessEntryModelFactory()
        key = self.proxy_manager.create_unique_key(access_entry.ip, access_entry.path)
        self.assertEqual(len(key), 8)
        self.assertEqual(key, access_entry.key)

    # def test_do_request(self):

    # def test_access_filter_pass(self):
    #     access_entry = AccessEntryModelFactory()
    #     request_object = MagickMock()
    #     self.proxy_manager.access_filter(access_entry.ip, access_entry.path, request_object)
    #     self.assertCalled(self.do_request)
    #     self.assertCalled(self._create_unique_key)

    def test_access_filter_block(self):
        access_entry = AccessEntryModelFactory(already_requested=100)
        self.assertFalse(self.proxy_manager.access_filter(access_entry))
        self.assertRaises(ExceededRequestsLimitException, self.proxy_manager.access_filter(access_entry)
