from django.db import models
from .helpers import generate_state

class OAuthToken(models.Model):
    id = models.AutoField(primary_key=True)

    code = models.CharField(max_length=80)

    private_roombookings = models.BooleanField(default=False)
    private_timetable = models.BooleanField(default=False)
    private_uclu = models.BooleanField(default=False)

class State(models.Model):
    id = models.AutoField(primary_key=True)
    
    code = models.CharField(
        max_length=70,
        unique=True,
        default=generate_state
    )

    verified = models.BooleanField(default=False)

    token = models.OneToOneField(
        OAuthToken,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )