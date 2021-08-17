from .models import AccessEntry
import json


class RegistryInterface:
    """ Interface to create new access registers """ 

    def __init__(self):
        """ Initialize the interface """
        self.model = AccessEntry()

    def create_access_entry(self, key, ip, path, request) -> None:
        """ Create a new access entry """
        formatted_request = json.dumps(request.__dict__)
        self.model.objects.create(key=key, ip=ip, path=path, request=formatted_request)
    
    def get_access_entry(self, key) -> AccessEntry:
        """ Get an access entry """
        return self.model.objects.get(key=key)
    
    def get_all_access_entries(self) -> list:
        """ Get all access entries """
        return self.model.objects.all().order_by('created_at')