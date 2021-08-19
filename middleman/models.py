from django.db import models

class AccessEntry(models.Model):
    """
    A single access entry.
    """

    class Meta:
        app_label = 'middleman'
        db_table = 'middleman_access_entry'
        ordering = ['ip']

    key= models.CharField(max_length=20, unique=True)
    ip = models.CharField(max_length=45)
    path = models.CharField(max_length=255)
    already_requested = models.IntegerField(default=0)
    max_requests = models.IntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
    
    def __repr__(self):
        return "Access from {} to {} at {}".format(self.ip, self.path, self.created_at)