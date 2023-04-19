import datetime
import random
from django.shortcuts import render
from .models import *
from rest_framework.decorators import api_view
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from ipware import get_client_ip
import pandas as pd
from klefki.zkp.pedersen import PedersonCommitment
from klefki.algebra.concrete import EllipticCurveGroupSecp256k1 as Curve
from klefki.algebra.concrete import FiniteFieldCyclicSecp256k1 as CF
from klefki.algebra.concrete import FiniteFieldSecp256k1 as F
from klefki.algebra.utils import randfield
from klefki.utils import to_sha256int
import hashlib

G = Curve.G
s = bytes.fromhex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
x = int(hashlib.sha256(s).hexdigest(),16)
H = Curve.lift_x(F(x))

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {'refresh': str(refresh), 'access': str(refresh.access_token)}
 
def generateOtp():
    #generate 4 hex digits not already in use
    otp = random.randint(0, 65535)
    while Token.objects.filter(otp=otp).exists():
        otp = random.randint(0, 65535)
    # return as hex string
    return hex(otp)[2:].zfill(4)

def getEmptyBooth():
    booth = Booth.objects.filter(status='Empty')
    if booth.exists():
        # return a random booth
        return booth[random.randint(0, len(booth)-1)]
    else:
        booth = Booth.objects.all()
        for b in booth:
            token = Token.objects.get(booth=b)
            # if more than 3 mins have passed since the last token was generated
            if (datetime.datetime.now() - token.validFrom).total_seconds() > 180:
                token.delete()
                b.status = 'Empty'
                b.save()
                return b
        return None


# Create your views here.
@api_view(['POST'])
def loginAsAdmin(request):
    if (not(request.data['username']) or not(request.data['password'])):
        return Response({'error': 'Wrong credentials'}, status=status.HTTP_400_BAD_REQUEST)
    username = request.data['username']
    password = request.data['password']
    user = User.objects.filter(username=username)
    if user.exists():
        user = user.first()
        if user.check_password(password):
            if user.is_staff:
                tokens = get_tokens_for_user(user)
                return Response(tokens, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'You are not an admin'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'error': 'Wrong credentials'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'Wrong credentials'}, status=status.HTTP_400_BAD_REQUEST)
    


@api_view(['POST'])
def registerBooth(request):
    if (not(request.data['username']) or not(request.data['password'])):
        return Response({'error': 'Wrong credentials'}, status=status.HTTP_400_BAD_REQUEST)
    username = request.data['username']
    password = request.data['password']
    user = User.objects.filter(username=username)
    if user.exists():
        user = user.first()
        if user.check_password(password):
            if user.is_staff:
                tokens = get_tokens_for_user(user)
                client_ip, is_routable = get_client_ip(request)
                booth = Booth.objects.filter(ip=client_ip)
                if booth.exists():
                    booth = booth.first()
                    booth.verified = True
                    booth.save()
                    return Response({'data': 'Booth already registered'}, status=status.HTTP_200_OK)
                else:
                    booth = Booth.objects.create(ip=client_ip, verified=True)
                    booth.save()
                    return Response({'data': 'Booth registered successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'You are not an admin'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'error': 'Wrong credentials'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'Wrong credentials'}, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
def createElection(request):
    if(request.user.is_authenticated):
        if(request.user.is_staff):
            if('election_name' not in request.data or 'date' not in request.data or 'startTime' not in request.data or 'endTime' not in request.data):
                return Response({'error': 'Please fill all the fields'}, status=status.HTTP_400_BAD_REQUEST)
            election_name = request.data['election_name']
            election = Election.objects.filter(electionName=election_name)
            if election.exists():
                return Response({'error': 'Election already exists'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                data = request.data
                date = data['date']
                startTime = data['startTime']
                endTime = data['endTime']
                votes = 1
                if('votes' in data):
                    votes = data['votes']
                election = Election.objects.create(electionName=election_name, electionDate=date, electionTimeStart=startTime, electionTimeEnd=endTime, votesPerVoter = votes)
                election.save()
                return Response({'data': 'Election created successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'You are not an admin'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['GET'])
def getElections(request):
    if(request.user.is_authenticated and request.user.is_staff):
        elections = Election.objects.all()
        if elections.exists():
            elections = elections.values()
            print(elections)
            return Response({'data': elections}, status=status.HTTP_200_OK)
        else:
            return Response({'data': 'No elections found'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['POST'])
def createCandidates(request):
    if(request.user.is_authenticated and request.user.is_staff):
        if('election_name' not in request.data or 'candidates' not in request.data):
            return Response({'error': 'Please fill all the fields'}, status=status.HTTP_400_BAD_REQUEST)
        election_name = request.data['election_name']
        election = Election.objects.filter(electionName=election_name)
        if election.exists():
            election = election.first()
            numberOfCandidates = election.numberOfCandidates
            candidates = request.data['candidates'] # csv file
            df = pd.read_csv(candidates)
            # columns names : name, entry_number
            for index, row in df.iterrows():
                entry_number = row['entry_number']
                name = row['name']
                candidate = Candidate.objects.filter(entryNumber=entry_number, election=election)
                if candidate.exists():
                    continue
                else:
                    profile = Profile.objects.filter(entryNumber=entry_number)
                    if not(profile.exists()):
                        profile = Profile.objects.create(entryNumber=entry_number, name=name)
                        profile.save()
                    else:
                        profile = profile.first()
                    numberOfCandidates += 1
                    candidate = Candidate.objects.create(entryNumber=profile, election=election, j=numberOfCandidates)
                    candidate.save()
            election.numberOfCandidates = numberOfCandidates
            election.save()
            return Response({'data': 'Candidates created successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Election does not exist'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['POST'])
def createVoters(request):
    if(request.user.is_authenticated and request.user.is_staff):
        if('election_name' not in request.data or 'voters' not in request.data):
            return Response({'error': 'Please fill all the fields'}, status=status.HTTP_400_BAD_REQUEST)
        election_name = request.data['election_name']
        election = Election.objects.filter(electionName=election_name)
        if election.exists():
            election = election.first()
            voters = request.data['voters'] # csv file
            df = pd.read_csv(voters)
            # columns names : name, entry_number
            for index, row in df.iterrows():
                entry_number = row['entry_number']
                name = row['name']
                voter = Voter.objects.filter(entryNumber=entry_number, election=election)
                if voter.exists():
                    continue
                else:
                    profile = Profile.objects.filter(entryNumber=entry_number)
                    if not(profile.exists()):
                        profile = Profile.objects.create(entryNumber=entry_number, name=name)
                        profile.save()
                    else:
                        profile = profile.first()
                    voter = Voter.objects.create(entryNumber=profile, election=election)
                    voter.save()
            return Response({'data': 'Voters created successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Election does not exist'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['GET'])
def getElectionsForVoter(request):
    if(request.user.is_authenticated and request.user.is_staff):
        entryNumber = request.GET.get('entryNumber')
        profile = Profile.objects.filter(entryNumber=entryNumber)
        if profile.exists():
            profile = profile.first()
            voter = Voter.objects.filter(entryNumber=profile, election__electionDate__gte=datetime.datetime.now().date(), election__electionTimeStart__lte=datetime.datetime.now().time(), election__electionTimeEnd__gte=datetime.datetime.now().time(), voteCasted = False)
            if voter.exists():
                elections = voter.values('election__electionName')
                return Response({'data': elections}, status=status.HTTP_200_OK)
            else:
                return Response({'data': 'No elections found'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['GET'])
def getTokens(request):
    if(request.user.is_authenticated and request.user.is_staff):
        entryNumber = request.GET.get('entryNumber')
        profile = Profile.objects.filter(entryNumber=entryNumber)
        if profile.exists():
            profile = profile.first()
            voters = Voter.objects.filter(entryNumber=profile, election__electionDate__gte=datetime.datetime.now().date(), election__electionTimeStart__lte=datetime.datetime.now().time(), election__electionTimeEnd__gte=datetime.datetime.now().time(), numVotesCasted = 0)
            if voters.exists():
                tokens = []
                for voter in voters:
                    if voter.otpVerified or voter.otpGenerated!=None:
                        token = Token.objects.filter(voter=voter)
                        if token.exists():
                            token = token.first().delete()
                        voter.otpGenerated = None
                        voter.otpVerified = False
                        voter.save()
                    
                    

                        # timeOfGeneration = token.validFrom
                        # # token is valid for 3 minutes
                        # if (datetime.datetime.now() - timeOfGeneration).total_seconds() > 180:
                        #     token.booth.status = 'Empty'
                        #     token.booth.save()
                        #     token.delete()
                        #     voter.otpGenerated = None
                        #     voter.otpVerified = False
                        #     voter.save()
                        # else:
                        #     token.otp = generateOtp()
                        #     booth = token.booth.id
                        #     token.booth.status = 'Token Generated'
                        #     token.booth.save()
                        #     token.validFrom = datetime.datetime.now()
                        #     token.save()
                        #     voter.otpGenerated = token.otp
                        #     voter.save()
                        #     return Response({'data': {'otp': token.otp, 'booth': booth}}, status=status.HTTP_200_OK)
                    # generate new token
                    # generate ballot rid and u(obfuscation number) and r_rid and r_u
                    rid = randfield(CF)
                    r_rid = randfield(CF)
                    u = randfield(CF)
                    r_u = randfield(CF)
                    C_rid=(G**rid)*(H**r_rid)
                    C_u=(G**u)*(H**r_u)
                otp = generateOtp()
                booth = getEmptyBooth()
                if booth is None:
                    return Response({'error': 'No booths available'}, status=status.HTTP_200_OK)
                booth.status = 'Token Generated'
                booth.save()
                token = Token.objects.create(voter=voter, otp=otp, rid=rid, r_rid=r_rid, u=u, r_u=r_u, booth=booth,C_u=C_u,C_rid=C_rid)
                token.save()
                voter.otpGenerated = otp
                voter.save()
                return Response({'data': {'otp': otp, 'booth': booth.id}}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'No elections found'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Voter not found'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)
    
    
@api_view(['POST'])
def verifyToken(request):
    if(request.user.is_authenticated and request.user.is_staff):
        otp = request.data.get('otp')
        client_ip, is_routable = get_client_ip(request)
        booth = Booth.objects.filter(ip=client_ip)
        if not booth.exists():
            return Response({'error': 'Booth not found'}, status=status.HTTP_200_OK)
        booth = booth.first()
        token = Token.objects.filter(otp=otp, booth=booth)
        if token.exists():
            token = token.first()
            # token is valid for 3 minutes
            if (datetime.datetime.now() - token.validFrom).total_seconds() > 180:
                token.booth.status = 'Empty'
                token.booth.save()
                token.delete()
                return Response({'error': 'Token expired'}, status=status.HTTP_200_OK)

            voter = token.voter
            voter.otpVerified = True
            voter.save()
            token.booth.status = 'Token Verified'
            token.booth.save()

            #return rid, r_rid, u, r_u, C_rid, C_u, list of candidates with their j values
            candidates = Candidate.objects.filter(election=voter.election)
            jsonCanditates = []
            for candidate in candidates:
                w_j = (candidate.j + token.u)
                w_j_tilda = w_j % voter.election.numberOfCandidates
                jsonCanditates.append({'name': candidate.candidatename, 'j': w_j_tilda})

            

    entryNumber=request.GET.get('entryNumber')
    election=request.GET.get('election')
    otp=request.GET.get('otp')
    voter=Voter.objects.filter(entryNumber=entryNumber,election=election)
    if (not(voter.exists())):
        return Response({'error': 'Voter not found'}, status=status.HTTP_200_OK)
    voter=voter.first()
    
    token=Token.objects.filter(voter=voter)
    if (not(token.exists())):
        return Response({'error': 'Token not found, please talk to the polling officer'}, status=status.HTTP_200_OK)
    token=token.first()
    
    Lold=[obj.candidatename for obj in Candidate.objects.filter(election=election)]
    L=Lold.copy()
    for i in range(0,len(Lold)):
        L[i]=Lold[(token.u+i)%len(Lold)]

    if (token.otp==otp and (datetime.datetime.now()-token.validFrom).total_seconds()<180):
        voter.otpVerified=True
        return Response({'data': 'Token verified','ballot':L}, status=status.HTTP_200_OK)
    elif (token.otp==otp and (datetime.datetime.now()-token.validFrom).total_seconds()>=180):
        return Response({'error': 'Token expired,please talk to the polling officer'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Incorrect username/password'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def getVote(request):
    w_v=request.data['chosennumber']
    entryNo=request.data['entryNo']
    election=request.data['election']
    voter=Voter.objects.filter(entryNumber=entryNo,election=election)
    voter=voter.first()
    token=Token.objects.filter(voter=voter)
    token=token.first()
    m=voter.election.numberOfCandidates
    u=token.u
    v=((w_v-u)%m+m)%m
    r_v=randfield(CF)
    rid=token.rid
    r_rid=token.r_rid
    w_vtilde=(token.r_u+v)%m
    r_w_v=r_v+token.r_u
    C_rid=token.C_rid
    C_v=(G**v)*(H**r_v)
    C_u=token.C_u
    receipt=Receipt.create(C_rid=C_rid,C_v=C_v,C_u=C_u,w_v=w_v,w_vtilde=w_vtilde,r_w_v=r_w_v)
    receipt.save()
    vote=Vote.create(C_rid=C_rid,C_v=C_v,rid=rid,v=v,r_rid=r_rid,r_v=r_v)
    vote.save()
    
    return Response({'data': 'Vote casted','C_rid':receipt.C_rid,'C_v':receipt.C_v,'w_v':receipt.w_v,'r_w_v':receipt.r_w_v}, status=status.HTTP_200_OK)
# @api_view(['GET'])


# @api_view(['POST'])
# def castVote(request):
    
