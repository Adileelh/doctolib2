from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework import status
from rest_framework.response import Response

from django.core.mail import send_mail
from django.conf import settings
from rest_framework.generics import GenericAPIView

from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.core.mail import send_mail
from django.urls import reverse
import random
import uuid
from .models import Utilisateur, medecinPatient
from .serializers import UtilisateurSerializer, ChangePasswordSerializer, AssociationMedecinPatientSerializer
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema

# jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzAwNjc4OTIwLCJpYXQiOjE3MDAwNzQxMjAsImp0aSI6IjlhZGY0ZThjMDI4YjQ3NzJhMmU1OGY4NWRjMGNlNjRjIiwidXNlcl9pZCI6MX0.NS0dkZz4uSCPFW-63-bWFxokK8EMTEiHtNNU8phQNXI


class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        access = response.data.pop('access', None)
        refresh = response.data.pop('refresh', None)

        if access:
            response.set_cookie(
                key='access_token',
                value=access,
                httponly=True,
                secure=False,  # Mettre à True en production
                samesite='Lax'
            )

        if refresh:
            response.set_cookie(
                key='refresh_token',
                value=refresh,
                httponly=True,
                secure=False,  # Mettre à True en production
                samesite='Lax'
            )

        return response


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        request.data['refresh'] = request.COOKIES.get('refresh_token')
        response = super().post(request, *args, **kwargs)
        access = response.data.pop('access', None)

        if access:
            response.set_cookie(

                key='access_token',
                value=access,
                httponly=True,
                secure=False,  # Mettre à True en production
                samesite='Lax'
            )

        return response


class LogoutView(APIView):
    permission_classes = []  # Aucune authentification requise pour se déconnecter
    serializer_class = None

    def post(self, request):
        response = Response(
            {"message": "Déconnexion réussie."}, status=status.HTTP_200_OK)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response


class RetrieveUserAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UtilisateurSerializer

    @extend_schema(operation_id='list_or_retrieve_user')
    def get(self, request, pk=None, *args, **kwargs):
        if pk:
            user = get_object_or_404(Utilisateur, pk=pk)
            serializer = UtilisateurSerializer(user)
            return Response(serializer.data)
        else:
            users = Utilisateur.objects.all()
            serializer = UtilisateurSerializer(users, many=True)
            return Response(serializer.data)


class RetrieveCurrentUserAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UtilisateurSerializer

    def get(self, request, *args, **kwargs):
        user = request.user
        if user.is_authenticated:
            serializer = UtilisateurSerializer(user)
            return Response(serializer.data)
        else:
            return Response({"error": "Utilisateur non authentifié"}, status=401)


class CreationPatientAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UtilisateurSerializer

    def has_permission_to_create(self, user):
        return user.role == 'responsable' or user.is_superuser

    def generate_username(self):
        unique_id = str(uuid.uuid4())
        return f"P{unique_id}"

    @extend_schema(operation_id='create_patient')
    def post(self, request, *args, **kwargs):
        if not self.has_permission_to_create(request.user):
            return Response(status=status.HTTP_403_FORBIDDEN)

        serializer = UtilisateurSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            if not username:
                username = self.generate_username()

            email = serializer.validated_data.get('email', '')
            motDePasse_initial = f"{username}MDP"

            nouveauCompte = Utilisateur.objects.create_user(
                username=username, role="patient", password=motDePasse_initial, email=email)

            # Envoi de l'e-mail de bienvenue (ajustez selon vos besoins)
            send_mail(
                'Bienvenue chez Nous!',
                f'Votre compte a été créé avec succès. Votre mot de passe initial est: {motDePasse_initial} et votre username est: {username} cliquez sur ce lien pour changer votre mot de passe et vous connecter: http://localhost:8000/api/changer-mdp/',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )

            return Response({"message": "Patient créé avec succès"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RetrievePatientAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UtilisateurSerializer

    @extend_schema(operation_id='list_or_retrieve_patient')
    def get(self, request, pk=None, *args, **kwargs):
        if pk:
            patient = get_object_or_404(Utilisateur, pk=pk, role='patient')
            serializer = UtilisateurSerializer(patient)
            return Response(serializer.data)
        else:
            patients = Utilisateur.objects.filter(role='patient')
            serializer = UtilisateurSerializer(patients, many=True)
            return Response(serializer.data)


class CreationMedecinAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UtilisateurSerializer

    def has_permission_to_create(self, user):
        return user.role == 'responsable' or user.is_superuser

    def generate_username(self):
        unique_id = str(uuid.uuid4())
        return f"M{unique_id}"

    @extend_schema(operation_id='create_medecin')
    def post(self, request, *args, **kwargs):
        if not self.has_permission_to_create(request.user):
            return Response(status=status.HTTP_403_FORBIDDEN)

        serializer = UtilisateurSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            if not username:
                username = self.generate_username()

            email = serializer.validated_data.get('email', '')
            motDePasse_initial = f"{username}MDP"

            nouveauCompte = Utilisateur.objects.create_user(
                username=username, role="medecin", password=motDePasse_initial, email=email)

            # Envoi de l'e-mail de bienvenue (ajustez selon vos besoins)
            send_mail(
                'Bienvenue chez Nous!',
                f'Votre compte a été créé avec succès. Votre mot de passe initial est: {motDePasse_initial}. et votre username est: {username} cliquez sur ce lien pour changer votre mot de passe et vous connecter: http://localhost:8000/api/changer-mdp/',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )

            return Response({"message": "Médecin créé avec succès"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RetrieveMedecinAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UtilisateurSerializer

    @extend_schema(operation_id='list_or_retrieve_medecin')
    def get(self, request, pk=None, *args, **kwargs):
        if pk:
            medecin = get_object_or_404(Utilisateur, pk=pk, role='medecin')
            serializer = UtilisateurSerializer(medecin)
            return Response(serializer.data)
        else:
            medecins = Utilisateur.objects.filter(role='medecin')
            serializer = UtilisateurSerializer(medecins, many=True)
            return Response(serializer.data)


class ChangePasswordView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    @extend_schema(request=ChangePasswordSerializer, responses={200: None})
    def post(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            ancienMDP = serializer.validated_data['ancienMDP']
            nouveauMDP1 = serializer.validated_data['nouveauMDP1']

            if not user.check_password(ancienMDP):
                return Response({"message": "L'ancien mot de passe n'est pas bon."}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(nouveauMDP1)
            user.save()
            return Response({"message": "Le mot de passe a été modifié avec succès."})

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AssociationMedecinPatientAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = AssociationMedecinPatientSerializer

    def post(self, request, *args, **kwargs):
        if request.user.role not in ['medecin', 'responsable']:
            return Response({"message": "Accès non autorisé"}, status=status.HTTP_403_FORBIDDEN)

        serializer = AssociationMedecinPatientSerializer(data=request.data)
        if serializer.is_valid():
            if request.user.role == 'medecin':
                # Un médecin ne peut s'associer qu'à lui-même
                serializer.save(idMedecin=request.user)
            else:
                # Un responsable peut associer n'importe quel médecin à un patient
                serializer.save()

            return Response({"message": "Association créée avec succès"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        if request.user.role == 'medecin':
            patients_associes = medecinPatient.objects.filter(
                idMedecin=request.user).select_related('idPatient')
            serializer = AssociationMedecinPatientSerializer(
                patients_associes, many=True)
            return Response(serializer.data)

        elif request.user.role == 'responsable':
            toutes_les_associations = medecinPatient.objects.all()
            serializer = AssociationMedecinPatientSerializer(
                toutes_les_associations, many=True)
            return Response(serializer.data)

        return Response({"message": "Accès non autorisé"}, status=status.HTTP_403_FORBIDDEN)
