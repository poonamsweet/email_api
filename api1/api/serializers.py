
from django.contrib import auth
from rest_framework import serializers, status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.validators import UniqueValidator

from .models import User





class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    email = serializers.CharField(required=True,validators=[UniqueValidator(queryset=User.objects.all())])
    mobile = serializers.CharField(required=True,validators=[UniqueValidator(queryset=User.objects.all())])
    dob = serializers.DateField()
    fullname = serializers.CharField(max_length=68)

    class Meta:
        model = User
        fields = ['email' ,'fullname','password','mobile','dob']

    def validate(self, attrs):
        email = attrs.get('email', '')
        mobile = attrs.get('mobile', '')
        dob = attrs.get('dob', '')
        fullname=attrs.get('fullname','')

        if email.isalnum():
            raise serializers.ValidationError(
                '{"Email is already ":"200 ok"}')


        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']







class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    fullname = serializers.CharField(
        max_length=255, min_length=3, read_only=True)
    tokens = serializers.CharField(max_length=68, min_length=6, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password' ,'fullname', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'fullname': user.fullname,
            'tokens': user.tokens
        }

        return super().validate(attrs)







class AllUserSerializer(serializers.ModelSerializer):
        class Meta:
            model = User
            fields = ['fullname', 'email', 'mobile', 'dob']




class ChangePasswordSerializer(serializers.Serializer):
    model = User

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)