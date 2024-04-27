from django.shortcuts import render
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import *
from .serializers import *

# Create your views here.

# Registration API
class New_user_registration(generics.CreateAPIView):
    serializer_class = NewUserSerializer


# Login API
class Login(generics.CreateAPIView):
    serializer_class = LoginSerializer