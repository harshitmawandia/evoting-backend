from django.db import models

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
    otpGenerated = models.CharField(max_length=4, default=None)
    otpVerified = models.BooleanField(default=False, null=False)
    voteCasted = models.BooleanField(default=False, null=False)

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

class Token(models.Model):
    rid = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    r_rid = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    u = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    r_u = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    otp = models.CharField(max_length=4, null=False)
    booth = models.ForeignKey(Booth, on_delete=models.CASCADE, null=False)
    validFrom = models.DateTimeField(null=False, auto_now_add=True)
    voter = models.ForeignKey (Voter, on_delete=models.CASCADE, null=False)

class Vote(models.Model):
    C_rid = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    C_v = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    rid = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    v = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    r_rid = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    r_v = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    election = models.ForeignKey(Election, on_delete=models.CASCADE, null=False)






