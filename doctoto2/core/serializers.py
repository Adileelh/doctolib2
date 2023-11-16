from rest_framework import serializers
from authentication.models import Utilisateur


class UsernameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Utilisateur
        fields = ['username']
