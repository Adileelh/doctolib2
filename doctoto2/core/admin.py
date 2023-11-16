from rest_framework import serializers
from .models import Utilisateur


class UsernameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Utilisateur
        fields = ['username']
