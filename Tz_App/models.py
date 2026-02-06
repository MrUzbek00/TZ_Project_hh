from django.db import models
from django.utils import timezone
import uuid

# Create your models here.
class UserProfile(models.Model):
    user_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    paternity_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    password = models.CharField(max_length=225)
    is_active = models.BooleanField(default=True)
    role = models.ForeignKey('Roles', on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return self.name

class Roles(models.Model):
    role_id = models.AutoField(primary_key=True)
    role = models.CharField(max_length=100)

    def __str__(self):
        return self.role

class Session(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name="sessions")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)

    def is_valid(self):
        return self.is_active and self.expires_at > timezone.now()
    
class BusinessElement(models.Model):
    element_id = models.AutoField(primary_key=True)
    code = models.CharField(max_length=100, unique=True) 
    description = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.code


class AccessRoleRule(models.Model):
    rule_id = models.AutoField(primary_key=True)
    role = models.ForeignKey(Roles, on_delete=models.CASCADE)
    element = models.ForeignKey(BusinessElement, on_delete=models.CASCADE)

    read_permission = models.BooleanField(default=False)        # own
    read_all_permission = models.BooleanField(default=False)    # all

    create_permission = models.BooleanField(default=False)

    update_permission = models.BooleanField(default=False)      # own
    update_all_permission = models.BooleanField(default=False)  # all

    delete_permission = models.BooleanField(default=False)      # own
    delete_all_permission = models.BooleanField(default=False)  # all

    class Meta:
        unique_together = ("role", "element")

    def __str__(self):
        return f"{self.role} -> {self.element}"
    
