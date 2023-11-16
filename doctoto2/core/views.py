
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .serializers import UsernameSerializer


class AccueilView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UsernameSerializer

    def get(self, request):
        username = request.user.username
        return Response({"username": username})
