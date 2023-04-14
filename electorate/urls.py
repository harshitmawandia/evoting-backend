from django.urls import path
from . import views

urlpatterns = [
    path('admin/login', views.loginAsAdmin, name='loginAsAdmin'),
]