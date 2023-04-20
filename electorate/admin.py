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


admin.site.register(Profile)
admin.site.register(Election)
admin.site.register(Booth)
admin.site.register(Candidate, CandidateAdmin)
admin.site.register(Voter, VoterAdmin)
admin.site.register(Token)
admin.site.register(Vote)
admin.site.register(OTP)
admin.site.register(OtpToToken)
