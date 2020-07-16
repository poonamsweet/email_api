from rest_framework import viewsets
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from api.models import User
from api.serializers import AllUserSerializer


class UserViewSets(viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication,TokenAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = AllUserSerializer
