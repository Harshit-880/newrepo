from .models import *
import random
import string
from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail
from django.core.mail.message import EmailMultiAlternatives
from django.utils import timezone


@shared_task(bind=True)
def send_otp(self, email):
    otp_length = 6
    otp = ''.join(random.choices(string.digits, k=otp_length))

    # Define email subject and message
    subject = "Your One-Time Password (OTP)"
    message = f"Your OTP is: {otp}. Please use this to complete your action. This OTP is valid for a limited time."

    # Send email
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.EMAIL_HOST_USER,  # Host email specified in Django settings
            recipient_list=[email],
            fail_silently=False,
        )
    except Exception as e:
        print(f"Failed to send OTP email to {email}: {e}")

    # Return the generated OTP
    return otp