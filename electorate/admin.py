from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(Profile)
admin.site.register(Election)
admin.site.register(Booth)
admin.site.register(Candidate)
admin.site.register(Voter)
admin.site.register(Token)
admin.site.register(Vote)
