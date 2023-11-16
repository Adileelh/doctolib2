from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from .models import Utilisateur, medecinPatient


class UtilisateurSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        required=False)  # Rendre le champ facultatif

    class Meta:
        model = Utilisateur
        fields = ['id', 'username', 'email', 'role']


class ChangePasswordSerializer(serializers.Serializer):
    ancienMDP = serializers.CharField(required=True)
    nouveauMDP1 = serializers.CharField(required=True)
    nouveauMDP2 = serializers.CharField(required=True)

    def validate_nouveauMDP1(self, value):
        validate_password(value)
        return value

    def validate(self, data):
        if data['nouveauMDP1'] != data['nouveauMDP2']:
            raise serializers.ValidationError(
                "Les mots de passe ne correspondent pas.")
        return data


class AssociationMedecinPatientSerializer(serializers.ModelSerializer):
    idMedecin = serializers.SlugRelatedField(
        slug_field='username', queryset=Utilisateur.objects.filter(role="medecin"))
    idPatient = serializers.SlugRelatedField(
        slug_field='username', queryset=Utilisateur.objects.filter(role="patient"))

    def validate(self, data):
        if medecinPatient.objects.filter(idMedecin=data['idMedecin'], idPatient=data['idPatient']).exists():
            raise serializers.ValidationError("Cette association existe déjà.")
        return data

    class Meta:
        model = medecinPatient
        fields = ['idMedecin', 'idPatient']


class LogoutSerializer(serializers.Serializer):
    pass
