import pyotp
from django.http import HttpResponse
from django.utils.crypto import get_random_string
from rest_framework.generics import get_object_or_404

from core.models import OTPSecret
from utilities.emails import send_email


def send_otp_email(request):
    # Retrieve the user object
    user = request.user

    # Generate or retrieve the OTP secret for the user
    otp_secret = get_object_or_404(OTPSecret, user=user)
    if not otp_secret:
        otp_secret = OTPSecret.objects.create(user=user, secret=get_random_string(length=16))

    # Generate the OTP using the secret
    totp = pyotp.TOTP(otp_secret.secret, interval=600)
    otp = totp.now()

    # Compose the email subject and content
    subject = 'One-Time Password (OTP) Verification'
    recipients = [user.email]
    message = f'Your one-time password is: {otp}'

    # Send the email
    send_email(subject, recipients, message=message)
