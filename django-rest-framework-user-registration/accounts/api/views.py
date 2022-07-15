from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from rest_framework import generics, permissions, status, views
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from . import serializers
from .serializers import UserRegistrationSerializer, UserProfileSerializer, ProfileSerializer, contentSerializer
from ..models import UserProfile, content_db
from django.http.response import JsonResponse, Http404
from rest_framework.parsers import JSONParser
User = get_user_model()


class UserRegistrationAPIView(generics.CreateAPIView):
    """
    Endpoint for user registration.

    """

    permission_classes = (permissions.AllowAny, )
    serializer_class = serializers.UserRegistrationSerializer
    queryset = User.objects.all()


class UserEmailVerificationAPIView(views.APIView):
    """
    Endpoint for verifying email address.

    """

    permission_classes = (permissions.AllowAny, )

    def get(self, request, verification_key):
        activated_user = self.activate(verification_key)
        if activated_user:
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def activate(self, verification_key):
        return UserProfile.objects.activate_user(verification_key)


class UserLoginAPIView(views.APIView):
    """
    Endpoint for user login. Returns authentication token on success.

    """

    permission_classes = (permissions.AllowAny, )
    serializer_class = serializers.UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetAPIView(views.APIView):
    """
    Endpoint to send email to user with password reset link.

    """

    permission_classes = (permissions.AllowAny, )
    serializer_class = serializers.PasswordResetSerializer

    def post(self, request):
        user_profile = self.get_user_profile(request.data.get('email'))
        if user_profile:
            user_profile.send_password_reset_email(
                site=get_current_site(request)
            )  # To be made asynchronous in production
            return Response(status=status.HTTP_200_OK)

        # Forcing Http status to 200 even if failure to support user privacy.
        # Will show message at frontend like "If the email is valid, you must have received password reset email"
        return Response(status=status.HTTP_200_OK)

    def get_user_profile(self, email):
        try:
            user_profile = UserProfile.objects.get(user__email=email)
        except:
            return None
        return user_profile


class PasswordResetConfirmView(views.APIView):
    """
    Endpoint to change user password.

    """

    permission_classes = (permissions.AllowAny, )
    serializer_class = serializers.PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):

        serializer = self.serializer_class(
            data=request.data,
            context={
                'uidb64': kwargs['uidb64'],
                'token': kwargs['token']
            })

        if serializer.is_valid(raise_exception=True):
            new_password = serializer.validated_data.get('new_password')
            user = serializer.user
            user.set_password(new_password)
            user.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileAPIView(generics.RetrieveAPIView):
    """
    Endpoint to retrieve user profile.

    """

    permission_classes = (permissions.IsAuthenticated, )
    authentication_classes = (TokenAuthentication, )
    serializer_class = serializers.UserProfileSerializer

    def get_object(self):
        return self.request.user.userprofile

###################################################################################################

class UserList(ListAPIView):
    def get(self, request, *args, **kwargs):
        queryset = User.objects.all()
        serializer = ProfileSerializer(queryset, many=True)
        user = {'status': True, 'data': serializer.data,}
        return Response(user, status=status.HTTP_200_OK)


class UpdateApi(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = ProfileSerializer


@api_view(['DELETE'])
def DeleteApi(request, pk):
    event = User.objects.get(pk=pk)
    event.delete()
    return Response('Deleted')

class ContentCreateApi(generics.CreateAPIView):
    # permission_classes = (IsAuthenticated,)
    queryset = content_db.objects.all()
    serializer_class = contentSerializer

# class ContentCreateApiUserList(generics.ListAPIView):
#     queryset = content_db.objects.all()
#     serializer_class = contentSerializer

class ContentCreateApiList(ListAPIView):
    def get(self, request, *args, **kwargs):
        queryset = content_db.objects.all()
        serializer = contentSerializer(queryset, many=True)
        user = {'status': True, 'data': serializer.data, 'message': 'Assigned Request'}
        return Response(user, status=status.HTTP_200_OK)

class ContentRenewCreateApi(generics.RetrieveUpdateAPIView):
    queryset = content_db.objects.all()
    # print(queryset,'gjhgh')
    serializer_class = contentSerializer


@api_view(['DELETE'])
def ContentDestroyCreateApi(request, pk):
    event = content_db.objects.get(pk=pk)
    event.delete()
    return Response('Deleted successfully')