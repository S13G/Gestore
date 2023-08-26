import pyotp
from django.http import Http404
from rest_framework.generics import get_object_or_404

from apps.core.models import OTPSecret
from utilities.emails import send_email


def send_otp_email(user, email=None):
    # Generate or retrieve the OTP secret for the user
    try:
        otp_secret = get_object_or_404(OTPSecret, user=user)
    except Http404:
        otp_secret = OTPSecret.objects.create(user=user, secret=pyotp.random_base32())

    # Generate the OTP using the secret
    totp = pyotp.TOTP(otp_secret.secret, interval=600)
    otp = totp.now()

    # Compose the email subject and content
    subject = 'One-Time Password (OTP) Verification'
    recipients = [user.email]
    message = f'Your one-time password is: {otp}'

    # Send the email
    send_email(subject, recipients, message=message)
