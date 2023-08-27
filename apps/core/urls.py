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
        'new-email/verify/code',
        views.SendNewEmailVerificationCodeView.as_view(),
        name="send_new_email_verification_code"
    ),
    path('change/email', views.ChangeEmailView.as_view(), name="change_email"),
    path('login', views.LoginView.as_view(), name="log_in"),
    path('logout', views.LogoutView.as_view(), name="logout"),
    path('refresh/token', views.RefreshView.as_view(), name="refresh_token"),
    path('request/forgot-password/code', views.RequestForgotPasswordCodeView.as_view(),
         name="request_forgotten_password_code"),
    path('verify/forgot-password/code', views.VerifyForgotPasswordCodeView.as_view(),
         name="verify_forgot_password_code"),
    path('change/forgot-password', views.ChangeForgottenPasswordView.as_view(), name="change_forgot_password"),
    path('change/new-password/', views.ChangePasswordView.as_view(), name="change_password"),

]
