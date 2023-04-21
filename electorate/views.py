import datetime 
import random
from django.shortcuts import render
import pytz
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
from django.conf import settings
from django.core.mail import send_mail


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
    while OTP.objects.filter(otp=otp).exists():
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
            otpObject = OTP.objects.filter(booth=b)
            if otpObject.exists():
                otpObject = otpObject.first()
                # if more than 180 seconds have passed since otp was generated
                if (datetime.datetime.now() - otpObject.validFrom).total_seconds() > 180:
                    # delete otp and corresponding tokens
                    Otptotoken = OtpToToken.objects.filter(otp=otpObject)
                    for o in Otptotoken:
                        if(o.token.voter.numVotesCasted == 0):
                            o.token.voter.otpGenerated = False
                            o.token.voter.otpVerified = False
                            o.token.voter.save()
                        o.token.delete()
                    otpObject.delete()
                    # set booth status to empty
                    b.status = 'Empty'
                    b.save()
                    return b
        return None


def sendReceipt(C_rid, C_u, C_v, w_v, w_v_tilda, r_w_v, entryNumber, electionName, voterName):
    #EntryNumber = 2020CS10348 email = cs1200348@iitd.ac.in
    email = entryNumber[4:7]+entryNumber[2:4]+entryNumber[7:]+ '@iitd.ac.in'
    subject = f'E-Voting Receipt for {electionName}'
    message = f'''
    Hello {voterName},<br><br>
    You have successfully voted in the election {electionName}.<br><br>
    Your receipt is as follows:<br><br>
    C<sub>rid</sub> = {C_rid}<br>
    C<sub>u</sub> = {C_u}<br>
    C<sub>v</sub> = {C_v}<br>
    w<sub>v</sub> = {w_v}<br>
    w<sub>v</sub><sup>tilda</sup> = {w_v_tilda}<br>
    r<sub>w<sub>v</sub></sub> = {r_w_v}<br><br>
    Thank you for voting!<br><br>
    Regards,<br>
    E-Voting Team,<br>
    CAIC, IIT Delhi'''
    try: #send mail with time limit of 2 seconds
        send_mail(subject, message, 'no_reply_caic@iitd.ac.in', [email], fail_silently=False, html_message=message)
    except:
        print("Error sending email")


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
                    return Response({'data': 'Booth already registered', 'token': tokens}, status=status.HTTP_200_OK)
                else:
                    booth = Booth.objects.create(ip=client_ip, verified=True)
                    booth.save()
                    return Response({'data': 'Booth registered successfully', 'token': tokens}, status=status.HTTP_200_OK)
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
                print(data)
                if('votes' in data):
                    votes = data['votes']
                    print(votes)
                votes = int(votes)
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
                if(len(str(entry_number)) < 11):
                    continue
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
    if(not(request.user.is_authenticated and request.user.is_staff)):
        return Response({'error': 'Log in with Booth'}, status=status.HTTP_401_UNAUTHORIZED)
    if('otp' not in request.GET):
        return Response({'error': 'Please provide otp'}, status=status.HTTP_400_BAD_REQUEST)
    otp = request.GET.get('otp')

    client_ip,is_routable=get_client_ip(request)
    booth = Booth.objects.filter(ip=client_ip)
    if not booth.exists():
        return Response({'error': 'Booth not found'}, status=status.HTTP_400_BAD_REQUEST)
    booth = booth.first()

    otpObject = OTP.objects.filter(otp=otp, booth=booth)
    if not(otpObject.exists()):
        return Response({'error': 'Invalid otp or booth'}, status=status.HTTP_400_BAD_REQUEST)
    otpObject = otpObject.first() 

    # check if otp has expired
    if(datetime.datetime.now(pytz.timezone('Asia/Calcutta')) - otpObject.validFrom).total_seconds() > 180:
        otpToken=OtpToToken.objects.filter(otp=otpObject)
        for otptok in otpToken:
            token=otptok.token
            voter=token.voter
            voter.otpGenerated = False
            voter.otpVerified = False
            voter.save()
            token.delete()
        otpObject.delete()
        booth.status = 'Empty'
        booth.save()
        return Response({'error': 'Otp expired'}, status=status.HTTP_400_BAD_REQUEST)

    otpToToken = OtpToToken.objects.filter(otp=otpObject)
    if not(otpToToken.exists()):
        return Response({'error': 'Invalid otp'}, status=status.HTTP_400_BAD_REQUEST)
    elections = []
    for o in otpToToken:
        elections.append({'election': o.token.voter.election.electionName, 'numVotes': o.token.voter.election.votesPerVoter, 'voterId': o.token.voter.id})
    return Response({'data': elections}, status=status.HTTP_200_OK)
    

    
@api_view(['GET'])
def getTokens(request):
    if(request.user.is_authenticated and request.user.is_staff):
        entryNumber = request.GET.get('entryNumber')
        profile = Profile.objects.filter(entryNumber=entryNumber)
        if profile.exists():
            profile = profile.first()
            voters = Voter.objects.filter(entryNumber=profile, election__electionDate__gte=datetime.datetime.now().date(), election__electionTimeStart__lte=datetime.datetime.now().time(), election__electionTimeEnd__gte=datetime.datetime.now().time(), numVotesCasted = 0)
            if voters.exists():
                tokenObjects = []
                for voter in voters:
                    if voter.otpVerified or voter.otpGenerated:
                        token = Token.objects.filter(voter=voter)
                        if token.exists():
                            otp = OtpToToken.objects.get(token=token.first()).otp
                            token.first().delete()
                            if(not OtpToToken.objects.filter(otp=otp).exists()):
                                booth = otp.booth
                                booth.status = 'Empty'
                                booth.save()
                                otp.delete()
                        voter.otpGenerated = False
                        voter.otpVerified = False
                        voter.save()                   
                    rid = randfield(CF)
                    # print('rid: ', rid)
                    r_rid = randfield(CF)
                    # print('r_rid: ', r_rid)
                    u = randfield(CF)
                    # print(u)
                    r_u = randfield(CF)
                    # print(r_u)
                    C_rid=(G**rid)*(H**r_rid)
                    # print('C_rid: ', C_rid)
                    # print('C_rid.x: ', C_rid.x)
                    # print('C_rid.y: ', C_rid.y)
                    C_u=(G**u)*(H**r_u)
                    rid = str(rid)
                    # print('StringRid', rid)
                    r_rid = str(r_rid)
                    # print('StringRrid', r_rid)
                    u = str(u)
                    r_u = str(r_u)
                    C_ridX = str(C_rid.x)
                    # print('C_ridX', C_ridX)
                    C_ridY = str(C_rid.y)
                    # print('C_ridY', C_ridY)
                    C_uX = str(C_u.x)
                    C_uY = str(C_u.y)

                    token = Token.objects.create(voter=voter, rid=rid, r_rid=r_rid, u=u, r_u=r_u, C_ridX=C_ridX, C_ridY=C_ridY, C_uX=C_uX, C_uY=C_uY)
                    token.save()
                    tokenObjects.append(token)
                    voter.otpGenerated = True
                    voter.save()

                otp = generateOtp()
                booth = getEmptyBooth()
                if booth is None:
                    for token in tokenObjects:
                        token.delete()
                    for voter in voters:
                        voter.otpGenerated = False
                        voter.save()
                    return Response({'error': 'No booths available'}, status=status.HTTP_200_OK)
                booth.status = 'Token Generated'
                booth.save()

                otpObject = OTP.objects.create(otp=otp, booth=booth)
                otpObject.save()

                for token in tokenObjects:
                    otptotoken = OtpToToken.objects.create(token=token, otp=otpObject)
                    otptotoken.save()
                
                return Response({'data': {'otp': otp, 'booth': booth.id}}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'No elections found or Vote Already Casted'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Voter not found'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)
    
    
@api_view(['GET'])
def verifyOTP(request):
    if(not(request.user.is_authenticated and request.user.is_staff)):
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)

    client_ip,is_routable=get_client_ip(request)
    booth = Booth.objects.filter(ip=client_ip)
    if not booth.exists():
        return Response({'error': 'Booth not found'}, status=status.HTTP_400_BAD_REQUEST)
    booth = booth.first()
    if 'otp' not in request.GET:
        return Response({'error': 'OTP not found'}, status=status.HTTP_400_BAD_REQUEST)
    otp=request.GET.get('otp')

    OTPobj=OTP.objects.filter(otp=otp,booth=booth)
    if (not(OTPobj.exists())):
        return Response({'error': 'OTP not correct or you are at the wrong booth'}, status=status.HTTP_401_UNAUTHORIZED)
    OTPobj = OTPobj.first()
    if ((datetime.datetime.now(pytz.timezone('Asia/Calcutta'))-OTPobj.validFrom).total_seconds()>=180):
        otpToken=OtpToToken.objects.filter(otp=OTPobj)
        for otptok in otpToken:
            token=otptok.token
            voter=token.voter
            voter.otpGenerated = False
            voter.otpVerified = False
            voter.save()
            token.delete()
        OTPobj.delete()
        booth.status = 'Empty'
        booth.save()
        return Response({'error': 'Token expired,please talk to the polling officer'}, status=status.HTTP_400_BAD_REQUEST)
    
    otpToken=OtpToToken.objects.filter(otp=OTPobj)
    if (not(otpToken.exists())):
        OTPobj.delete()
        return Response({'error': 'No token for this OTP'}, status=status.HTTP_400_BAD_REQUEST)
    
    ListIds=[]
    for otptok in otpToken:
        token=otptok.token
        voter=token.voter
        voter.otpVerified = True
        voter.save()
        ListIds.append(voter.id)

    booth.status = 'Token Verified'
    booth.save()

    return Response({'data': 'Token verified','voter_ids':ListIds}, status=status.HTTP_200_OK)
    


@api_view(['GET'])
def getBallot(request):

    if(not(request.user.is_authenticated and request.user.is_staff)):
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)
    
    if('voter_id' not in request.GET or 'otp' not in request.GET):
        return Response({'error': 'Voter ID or OTP not found'}, status=status.HTTP_400_BAD_REQUEST)

    voter_id=request.GET.get('voter_id')
    otp=request.GET.get('otp')
    client_ip,is_routable=get_client_ip(request)
    booth = Booth.objects.filter(ip=client_ip)
    if not booth.exists():
        return Response({'error': 'Booth not found'}, status=status.HTTP_401_UNAUTHORIZED)
    booth = booth.first()
    OTPobj=OTP.objects.filter(otp=otp,booth=booth)
    if (not(OTPobj.exists())):
        return Response({'error': 'OTP not correct or you are at the wrong booth'}, status=status.HTTP_401_UNAUTHORIZED)
    OTPobj = OTPobj.first()
    if ((datetime.datetime.now(pytz.timezone('Asia/Calcutta'))-OTPobj.validFrom).total_seconds()>=180):
        otpToken=OtpToToken.objects.filter(otp=OTPobj)
        for otptok in otpToken:
            token=otptok.token
            voter=token.voter
            voter.otpGenerated = False
            voter.otpVerified = False
            voter.save()
            token.delete()
        OTPobj.delete()
        booth.status = 'Empty'
        booth.save()
        return Response({'error': 'Token expired,please talk to the polling officer'}, status=status.HTTP_400_BAD_REQUEST)
    otpTokens=OtpToToken.objects.filter(otp=OTPobj)

    if (not(otpTokens.exists())):
        OTPobj.delete()
        return Response({'error': 'No token for this OTP'}, status=status.HTTP_400_BAD_REQUEST)
    voter=Voter.objects.filter(id=voter_id)
    if (not(voter.exists())):
        return Response({'error': 'No voter with this id'}, status=status.HTTP_400_BAD_REQUEST)
    voter=voter.first()
    token=Token.objects.filter(voter=voter)
    if (not(token.exists())):
        return Response({'error': 'No Token'}, status=status.HTTP_400_BAD_REQUEST)
    token=token.first()
    # assert this token exists in otpTokens
    found = False
    for otpToken in otpTokens:
        if otpToken.token == token:
            found = True
            break

    if(not found):
        return Response({'error': 'OTP not valid for Voter'}, status=status.HTTP_401_UNAUTHORIZED)
    
    if(voter.otpVerified == False):
        return Response({'error': 'OTP not verified'}, status=status.HTTP_401_UNAUTHORIZED)

    election=voter.election
    ballot = []

    Lold=[obj for obj in Candidate.objects.filter(election=election)]
    L=Lold.copy()
    print(len(Lold))
    # decimal.getcontext().prec = 1000
    for i in range(0,len(Lold)):
        u = token.u
        print(u)
        L[i]=Lold[(int)((int(u)+i)%len(Lold))]
        j = (int)((int(u)+Lold[i].j-1)%len(Lold))
        ballot.append({'name':Lold[i].entryNumber.name,'j':j})
    
    return Response({'data': 'Token verified','ballotlist':ballot,'u':str(token.u),'C_uX':str(token.C_uX),'C_uY':str(token.C_uY) ,'C_ridX':str(token.C_ridX),'C_ridY':str(token.C_ridY),'electionName':election.electionName, 'numVotes':election.votesPerVoter}, status=status.HTTP_200_OK)

    

@api_view(['POST'])
def castVote(request):
    if(not(request.user.is_authenticated and request.user.is_staff)):
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)

    if('otp' not in request.data):
        return Response({'error': 'OTP not found'}, status=status.HTTP_400_BAD_REQUEST)
    otp=request.data['otp']
    client_ip,is_routable=get_client_ip(request)
    booth = Booth.objects.filter(ip=client_ip)
    if not booth.exists():
        return Response({'error': 'Booth not found'}, status=status.HTTP_400_BAD_REQUEST)
    booth = booth.first()
    OTPobj=OTP.objects.filter(otp=otp,booth=booth)
    if (not(OTPobj.exists())):
        return Response({'error': 'OTP not correct or you are at the wrong booth'}, status=status.HTTP_401_UNAUTHORIZED)
    OTPobj = OTPobj.first()

    if ((datetime.datetime.now(pytz.timezone('Asia/Calcutta'))-OTPobj.validFrom).total_seconds()>=180):
        otpToken=OtpToToken.objects.filter(otp=OTPobj)
        for otptok in otpToken:
            token=otptok.token
            voter=token.voter
            voter.otpGenerated = False
            voter.otpVerified = False
            voter.save()
            token.delete()
        OTPobj.delete()
        booth.status = 'Empty'
        booth.save()
        return Response({'error': 'Token expired,please talk to the polling officer'}, status=status.HTTP_400_BAD_REQUEST)
    
    if ('vote_list' not in request.data or 'voter_id' not in request.data):
        return Response({'error': 'Incomplete Data'}, status=status.HTTP_400_BAD_REQUEST)
    w_vlist=request.data['vote_list']
    vote_id=request.data['voter_id']  
    voter=Voter.objects.filter(id=vote_id)
    if (not(voter.exists())):
        return Response({'error': 'No voter with this id'}, status=status.HTTP_401_UNAUTHORIZED)
    voter=voter.first()
    token=Token.objects.filter(voter=voter)
    if (not(token.exists())):
        return Response({'error':'No Token'},status=status.HTTP_401_UNAUTHORIZED)
    if (not(voter.otpVerified)):
        return Response({'error':'Token Not verified'},status=status.HTTP_401_UNAUTHORIZED)
    
    token=token.first()
    #match token with otp token
    otpToken=OtpToToken.objects.filter(otp=OTPobj)
    if (not(otpToken.exists())):
        OTPobj.delete()
        return Response({'error':'No token for this OTP'},status=status.HTTP_401_UNAUTHORIZED)
    otpToken=otpToken.first()
    if (otpToken.token.rid!=token.rid):
        return Response({'error':'VoterID does not match OTP'},status=status.HTTP_401_UNAUTHORIZED)


    m=voter.election.numberOfCandidates
    if (len(w_vlist)!=voter.election.votesPerVoter):
        return Response({'error':'Incorrect number of votes'},status=status.HTTP_401_UNAUTHORIZED)
    u=int(token.u)
    # decimal.getcontext().prec = 1000
    for w_v in w_vlist:
        v=((w_v-u)%m+m)%m + 1
        r_v=randfield(CF)
        rid=(token.rid)
        r_rid=(token.r_rid)
        w_vtilde=((int(token.r_u)+v)%m)
        r_w_v=(int(str(r_v))+int(token.r_u))
        C_ridX=(token.C_ridX)
        C_ridY=(token.C_ridY)
        C_rid = Curve(
                (
                    F(int(C_ridX)),
                    F(int(C_ridY))
                )
            )
        C_v=(G**CF(v))*(H**r_v)
        r_v=int(str(r_v))
        C_vX=(C_v.x)
        C_vX=(str(C_vX))
        C_vY=(C_v.y)
        C_vY=(str(C_vY))
        C_uX=(token.C_uX)
        C_uY=(token.C_uY)
        C_u = Curve(
                (
                    F(int((C_uX))),
                    F(int((C_uY)))
                )
            )
        w_v_final = u + v
        vote=Vote.objects.create(C_ridX=C_ridX,C_ridY=C_ridY,C_vX=C_vX,C_vY=C_vY,rid=rid,v=v,r_rid=r_rid,r_v=r_v, election=voter.election)
        vote.save()
        voter.numVotesCasted+=1
        voter.save() 
        sendReceipt((C_ridX,C_ridY),(C_uX,C_uY),(C_vX,C_vY),w_v_final,w_vtilde,r_w_v,voter.entryNumber.entryNumber,voter.election,voter.entryNumber.name)
        #send email
    token.delete()
    otpToken=OtpToToken.objects.filter(otp=OTPobj)
    if(not otpToken.exists()):
        OTPobj.delete()
    booth.status = 'Empty'
    booth.save()
    
    return Response({'data': 'Vote casted.Check your email for your receipt'}, status=status.HTTP_200_OK)


@api_view(['GET'])
def getResults(request):
    if not(request.user.is_authenticated and request.user.is_staff):
        return Response({'error':'Not authenticated'},status=status.HTTP_401_UNAUTHORIZED)
    if(not 'electionName' in request.GET):
        return Response({'error':'No election name'},status=status.HTTP_400_BAD_REQUEST)
    election=Election.objects.filter(electionName=request.GET['electionName'])
    if (not(election.exists())):
        return Response({'error':'No election with this name'},status=status.HTTP_400_BAD_REQUEST)
    election=election.first()
    candidates=Candidate.objects.filter(election=election)
    votes=Vote.objects.filter(election=election)
    results={}
    for candidate in candidates:
        results[candidate.entryNumber.name]=0
    for vote in votes:
        v = vote.v
        for candidate in candidates:
            if (candidate.j==v):
                results[candidate.entryNumber.name]+=1

    #sort results
    results = sorted(results.items(), key=lambda x: x[1],reverse=True)
    return Response({'results':results},status=status.HTTP_200_OK)


@api_view(['GET'])
def checkReceipt(request):
    if not(request.user.is_authenticated and request.user.is_staff):
        return Response({'error':'Not authenticated'},status=status.HTTP_401_UNAUTHORIZED)
    election=Election.objects.filter(electionName=request.GET['electionName'])
    if (not(election.exists())):
        return Response({'error':'No election with this name'},status=status.HTTP_400_BAD_REQUEST)
    election=election.first()
    C_rid=request.GET['C_rid']
    vote=Vote.objects.filter(C_rid=C_rid,election=election)
    if (not(vote.exists())):
        return Response({'error':'No vote with this C_rid'},status=status.HTTP_400_BAD_REQUEST)
    vote=vote.first()
    v=vote.v

    return Response({'vote':Candidate.objects.get(election=election,j=v).entryNumber.name},status=status.HTTP_200_OK)


# @api_view(['POST'])
# def castVote(request):
    
