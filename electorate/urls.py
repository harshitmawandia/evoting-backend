from django.urls import path
from . import views

urlpatterns = [
    path('admin/login', views.loginAsAdmin, name='loginAsAdmin'),
    path('admin/registerBooth', views.registerBooth, name='registerBooth'),
    path('admin/createElection', views.createElection, name='createElection'),
    path('admin/addCandidates', views.createCandidates, name='addCandidates'),
    path('admin/elections', views.getElections, name='getElections'),
    path('admin/addElectorate', views.createVoters, name='addElectorate'),
]