import datetime
from django.shortcuts import render
from .models import *
from rest_framework.decorators import api_view
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from ipware import get_client_ip
import pandas as pd


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {'refresh': str(refresh), 'access': str(refresh.access_token)}


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
                election = Election.objects.create(electionName=election_name, electionDate=date, electionTimeStart=startTime, electionTimeEnd=endTime)
                election.save()
                return Response({'data': 'Election created successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'You are not an admin'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response({'error': 'You are not logged in'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['GET'])
def getElections(request):
    if(request.user.is_authenticated and request.user.is_staff):
        time = datetime.datetime.now()
        elections = Election.objects.filter(electionDate=time.date() ,electionTimeStart__lte=time.time(), electionTimeEnd__gte=time.time())
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
