from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Profile(models.Model):
    entryNumber = models.CharField(max_length=15, primary_key=True, unique=True, null=False)
    name = models.CharField(max_length=50, null=False)

    def __str__(self):
        return self.entryNumber + ' | ' + self.name

class Election(models.Model):
    electionName = models.CharField(max_length=50, null=False, unique=True)
    electionDate = models.DateField(null=False)
    electionTimeStart = models.TimeField(null=False)
    electionTimeEnd = models.TimeField(null=False)
    electionStatus = models.BooleanField(default=False, null=False)
    numberOfCandidates = models.IntegerField(null=False, default=0)
    votesPerVoter = models.IntegerField(null=False, default=1)

    def __str__(self):
        return self.electionName
    
class Candidate(models.Model):
    entryNumber = models.ForeignKey(Profile, on_delete=models.CASCADE, null=False)
    election = models.ForeignKey(Election, on_delete=models.CASCADE, null=False, to_field='electionName')
    j = models.IntegerField(null=False, default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['entryNumber', 'election'], name='unique_candidate')
        ]

    def __str__(self):
        return self.entryNumber.entryNumber + ' | ' + self.election.electionName
    
class Voter(models.Model):
    entryNumber = models.ForeignKey(Profile, on_delete=models.CASCADE, null=False)
    election = models.ForeignKey(Election, on_delete=models.CASCADE, null=False)
    otpGenerated = models.BooleanField(default=False, null=False)
    otpVerified = models.BooleanField(default=False, null=False)
    numVotesCasted = models.IntegerField(null=False, default=0)
    

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['entryNumber', 'election'], name='unique_electorate')
        ]

    def __str__(self):
        return self.entryNumber.entryNumber + ' | ' + self.election.electionName
    
class Booth(models.Model):
    ip = models.GenericIPAddressField(null=False, unique=True, protocol='IPv4',)
    id = models.AutoField(primary_key=True, unique=True, serialize=True)
    verified = models.BooleanField(default=False, null=False)
    statusChoices = [('Empty', 'Empty'), ('Token Generated', 'Token Generated'), ('Token Verified', 'Token Verified')]
    status = models.CharField(max_length=15, choices=statusChoices, null=False, default='Empty')
    user = models.ForeignKey(User, on_delete=models.CASCADE,null=False,default=1)

class Token(models.Model):
    rid = models.CharField(max_length=300, null=False,default='')
    C_ridX = models.CharField(max_length=300, null=False,default='')
    C_ridY = models.CharField(max_length=300, null=False,default='')
    r_rid = models.CharField(max_length=300, null=False,default='')
    u = models.CharField(max_length=300, null=False,default='')
    C_uX = models.CharField(max_length=300, null=False,default='')
    C_uY = models.CharField(max_length=300, null=False,default='')
    r_u = models.CharField(max_length=300, null=False,default='')
    voter = models.ForeignKey (Voter, on_delete=models.CASCADE, null=False)

class OTP(models.Model):
    otp = models.CharField(max_length=4, null=False)
    booth = models.ForeignKey(Booth, on_delete=models.CASCADE, null=False, unique=True)
    validFrom = models.DateTimeField(null=False, auto_now_add=True)

class OtpToToken(models.Model):
    otp = models.ForeignKey(OTP, on_delete=models.CASCADE, null=False)
    token = models.ForeignKey(Token, on_delete=models.CASCADE, null=False, unique=True, primary_key=True)

class Vote(models.Model):
    C_ridX = models.CharField(max_length=300, null=False,default='')
    C_ridY = models.CharField(max_length=300, null=False,default='')
    C_vX = models.CharField(max_length=300, null=False,default='')
    C_vY = models.CharField(max_length=300, null=False,default='')
    rid = models.CharField(max_length=300, null=False,default='')
    v = models.IntegerField(null=False, default=-1)
    r_rid = models.CharField(max_length=300, null=False,default='')
    r_v = models.CharField(max_length=300, null=False,default='')
    election = models.ForeignKey(Election, on_delete=models.CASCADE, null=False)
    by = models.ForeignKey(Voter, on_delete=models.CASCADE, null=True)

