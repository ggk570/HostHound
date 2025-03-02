from django.db import models
from django.contrib.auth.models import User

class Workspace(models.Model):
    """
    Represent a specific workspace for a user
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
    

class Node(models.Model):
    """
    Base class for all nodes (Host, Port, Endpoint).
    """
    id = models.AutoField(primary_key=True)
    reviewed = models.BooleanField(default=False)
    exploitable = models.BooleanField(default=False)
    notes = models.TextField(blank=True, null=True)

    class Meta:
        abstract = True
        
        
class Host(Node):
    """
    Represents a host in the network.
    """
    workspace = models.ForeignKey(Workspace, related_name="hosts", on_delete=models.CASCADE)
    ipv4_address = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        if self.ipv4_address and not self.hostname:
            return self.ipv4_address
        else:
            return self.hostname

class Port(Node):
    """
    Represents a port on a host.
    """
    host = models.ForeignKey(Host, related_name="ports", on_delete=models.CASCADE)
    port_no = models.PositiveIntegerField()
    service = models.CharField(max_length=255, blank=True, null=True)
    version = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"Port no - {self.port_no}"


class Endpoint(Node):
    """
    Represents an HTTP endpoint.
    """
    port = models.ForeignKey(Port, related_name="endpoints", on_delete=models.CASCADE)
    endpoint_name = models.CharField(max_length=255)
    status_code = models.PositiveIntegerField(blank=True, null=True)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, related_name="endpoints", null=True, blank=True)

    def __str__(self):
        return self.endpoint_name