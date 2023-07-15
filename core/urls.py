from django.urls import path

from core import views

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name="registration")
]
