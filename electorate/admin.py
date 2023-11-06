from django.contrib import admin
from .models import *

# Register your models here.

class VoterAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Voter._meta.fields]
    list_filter = ['election__electionName', 'otpVerified', 'numVotesCasted', 'otpGenerated']
    search_fields = ['entryNumber__entryNumber', 'election__electionName']

class CandidateAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Candidate._meta.fields]
    list_filter = ['election__electionName', 'j']
    search_fields = ['entryNumber__entryNumber', 'election__electionName', 'j']

class ProfileAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Profile._meta.fields]
    # list_filter = ['entryNumber', 'name']
    search_fields = ['entryNumber', 'name']

class BoothAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Booth._meta.fields]
    list_filter = ['ip', 'verified', 'status']
    search_fields = ['ip', 'verified', 'status']

class VotesAdmin(admin.ModelAdmin):
    list_display = ['id', 'election', 'v']
    list_filter = ['election__electionName']




admin.site.register(Profile, ProfileAdmin)
admin.site.register(Election)
admin.site.register(Booth, BoothAdmin)
admin.site.register(Candidate, CandidateAdmin)
admin.site.register(Voter, VoterAdmin)
admin.site.register(Token)
admin.site.register(Vote, VotesAdmin)
admin.site.register(OTP)
admin.site.register(OtpToToken)
