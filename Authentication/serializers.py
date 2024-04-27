from rest_framework import serializers
from .models import *
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
import re
import email
from Authentication.tasks import *


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True)
    refresh = serializers.CharField(read_only=True)
    access = serializers.CharField(read_only=True)


    def validate(self, data):
        try:
            User.objects.get(email=data["email"])
        except:
            raise ValidationError({"msg": "User Doesn’t Exist"})

        user = authenticate(email=data["email"], password=data["password"])

        if not user:
            raise ValidationError({"msg": "Invalid Credentials"})
        data["refresh"] = user.refresh
        data["access"] = user.access
        return data


class NewUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "name", "email", "password"]
        extra_kwargs = {
            "password": {"write_only": True},
        }

    @staticmethod
    def validate_password(data):
        if (
            len(data) < 8
            or not re.findall(r"\d", data)
            or not re.findall("[A-Z]", data)
            or not re.findall("[a-z]", data)
            or not re.findall(r"[()[\]{}|\\`~!@#$%^&*_\-+=;:'\",<>./?]", data)
        ):
            raise ValidationError(
                {
                    "msg": "The password needs to be more than 8 characters, contain atleast one uppercase,one lowercase and a special character"
                }
            )

        return data


    def create(self, data):
        userOTP = OTP.objects.filter(email=data["email"])
        if userOTP is not None:
            userOTP.delete()
        email = data["email"]
        OTP.objects.create(email=email)
        send_otp.delay(email)
        user = User.objects.create(
            name=data["name"],
            email=data["email"],
            password=data["password"],
        )
        user.password = make_password(data["password"])
        user.is_active = True
        user.save()

        return user


class OTP_Serializer(serializers.ModelSerializer):
    class Meta:
        model = OTP
        fields = ["email"]

    def validate(self, data):
        email = data["email"]
        if not re.findall("@.", email):
            raise ValidationError(("Enter a valid email"))
        user = list(User.objects.filter(email=email))
        if user != []:
            raise ValidationError({"msg": "User already exists"})
        return data

    def create(self, data):
        userOTP = OTP.objects.filter(email=data["email"])
        if userOTP is not None:
            userOTP.delete()
        email = data["email"]
        OTP.objects.create(email=email)
        send_otp.delay(email)

        return data