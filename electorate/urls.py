from django.urls import path
from . import views

urlpatterns = [
    path('admin/login', views.loginAsAdmin, name='loginAsAdmin'),
    path('admin/registerBooth', views.registerBooth, name='registerBooth'),
    path('admin/createElection', views.createElection, name='createElection'),
    path('admin/addCandidates', views.createCandidates, name='addCandidates'),
    path('admin/elections', views.getElections, name='getElections'),
    path('admin/addElectorate', views.createVoters, name='addElectorate'),
    path('admin/voter/elections', views.getElectionsForVoter, name='getElectionForVoter'),
    path('admin/voter/token',views.getTokens, name='generateTokens'),
    path('admin/voter/otp', views.verifyOTP, name='verifyOTP'),
    path('admin/voter/ballot', views.getBallot, name='getBallot'),
    path('admin/voter/vote', views.castVote, name='castVote'),
    path('admin/results/election', views.getElectionResult, name='getResults'),
    path('admin/results', views.getAllElectionResults, name='getAllResults'),
    path('admin/voter/checkReceipt', views.checkReceipt, name='checkReceipt'),
]