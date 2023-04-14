from django.shortcuts import render
from .models import *
from rest_framework.decorators import api_view
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from ipware import get_client_ip


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