from django.db import models


class User(models.Model):
    id = models.IntegerField(primary_key=True)
    email = models.CharField(max_length=100)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    roles = models.CharField(
        choices=[("STUDENT", "student"), ("INSTRUCTOR", "instructor")],
        default="student",
        max_length=100,
    )

    class Meta:
        managed = False
