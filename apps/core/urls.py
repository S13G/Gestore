from django.urls import path

from apps.core import views

urlpatterns = [
    path('register', views.RegisterView.as_view(), name="registration"),
    path('verify/email', views.VerifyEmailView.as_view(), name="verify_email"),
    path(
        'resend/email/verify/code/resend',
        views.ResendEmailVerificationCodeView.as_view(),
        name="resend_email_verification_code"
    ),
    path(
        'new_email/verify/code',
        views.SendNewEmailVerificationCodeView.as_view(),
        name="send_new_email_verification_code"
    ),
    path('change/email', views.ChangeEmailView.as_view(), name="change_email"),


]
