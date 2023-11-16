
from django.urls import path
from .views import (CustomTokenObtainPairView, CreationPatientAPIView,
                    CreationMedecinAPIView, ChangePasswordView, AssociationMedecinPatientAPIView,
                    LogoutView, RetrievePatientAPIView, RetrieveMedecinAPIView, RetrieveUserAPIView,
                    RetrieveCurrentUserAPIView)
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [

    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('retrieve-user/<int:pk>/',
         RetrieveUserAPIView.as_view(), name='api_get_user'),

    path('retrieve-current-user/', RetrieveCurrentUserAPIView.as_view(),
         name='api_get_current_user'),

    path('creation-patient/', CreationPatientAPIView.as_view(),
         name='api_creation_patient'),

    path('retrieve-patient/<int:pk>/',
         RetrievePatientAPIView.as_view(), name='api_get_patient'),

    path('creation-medecin/', CreationMedecinAPIView.as_view(),
         name='api_creation_medecin'),

    path('retrieve-medecin/<int:pk>/',
         RetrieveMedecinAPIView.as_view(), name='api_get_medecin'),

    path('changer-mdp/', ChangePasswordView.as_view(), name='changer_mdp'),
    path('association-medecin-patient/', AssociationMedecinPatientAPIView.as_view(),
         name='association_medecin_patient'),
    path('logout/', LogoutView.as_view(), name='logout'),


]
