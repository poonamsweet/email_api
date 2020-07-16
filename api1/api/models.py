
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)

from django.db import models
from django.db.models.functions import datetime
from rest_framework_simplejwt.tokens import RefreshToken




class UserManager(BaseUserManager):

    def create_user(self,email,password=None,mobile=None,dob=None,fullname=None ):
        if fullname is None:
            raise TypeError('Users should have a username')
        if email is None:
            raise TypeError('Users should have a Email')


        user = self.model(email=self.normalize_email(email),mobile=mobile,dob=dob,fullname=fullname)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self,email, mobile=None,dob=None,fullname=None,password=None):
        if password is None:
            raise TypeError('Password should not be none')


        user = self.create_user(email, mobile,dob,fullname,password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractBaseUser, PermissionsMixin):
    # username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    fullname = models.CharField(max_length=255,db_index=True)
    mobile = models.CharField(max_length=12,unique=True,null=True,default=False)
    dob = models.DateField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['fullname','mobile','dob']

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }











