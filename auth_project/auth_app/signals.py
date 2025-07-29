from django.db.models.signals import post_save
from django.contrib.auth.models import User

def my_handler(sender, instance, created, **kwargs):
    if created:
        print("A new user was created!")

post_save.connect(my_handler, sender=User)