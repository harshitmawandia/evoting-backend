from django.db import models

# Create your models here.
class Voter(models.Model):
    entryNumber = models.CharField(max_length=15, primary_key=True, unique=True, null=False)
    name = models.CharField(max_length=50, null=False)
    email = models.EmailField(max_length=50, null=False)

    def __str__(self):
        return self.entryNumber + ' | ' + self.name

class Election(models.Model):
    electionName = models.CharField(max_length=50, null=False)
    electionDate = models.DateField(null=False)
    electionTime = models.TimeField(null=False)
    electionStatus = models.BooleanField(default=False, null=False)
    numberOfCandidates = models.IntegerField(null=False, default=0)

    def __str__(self):
        return self.electionName
    
class Candidate(models.Model):
    entryNumber = models.ForeignKey(Voter, on_delete=models.CASCADE, null=False, related_name='entryNumber')
    electionName = models.ForeignKey(Election, on_delete=models.CASCADE, null=False, related_name='electionName')
    j = models.IntegerField(null=False, default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['entryNumber', 'electionName'], name='unique_candidate')
        ]

    def __str__(self):
        return self.entryNumber.entryNumber + ' | ' + self.electionName.electionName
    
class Electorate(models.Model):
    entryNumber = models.ForeignKey(Voter, on_delete=models.CASCADE, null=False, related_name='entryNumber')
    electionName = models.ForeignKey(Election, on_delete=models.CASCADE, null=False, related_name='electionName')
    otpGenerated = models.CharField(max_length=4, null=False)
    otpVerified = models.BooleanField(default=False, null=False)
    voteCasted = models.BooleanField(default=False, null=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['entryNumber', 'electionName'], name='unique_electorate')
        ]

    def __str__(self):
        return self.entryNumber.entryNumber + ' | ' + self.electionName.electionName
    
class Token(models.Model):
    rid = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    r_rid = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    u = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    r_u = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    otp = models.CharField(max_length=4, null=False)
    electorate = models.ForeignKey (Electorate, on_delete=models.CASCADE, null=False)

class Vote(models.Model):
    C_rid = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    C_v = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    rid = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    v = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    r_rid = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    r_v = models.DecimalField(max_digits=50, decimal_places=0, null=False)
    election = models.ForeignKey(Election, on_delete=models.CASCADE, null=False)


