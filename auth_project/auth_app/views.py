from rest_framework import generics
from .serializers import RegisterSerializer
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .utils.auth import get_tokens_for_user
from rest_framework_simplejwt.exceptions import AuthenticationFailed

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer
@method_decorator(csrf_exempt, name='dispatch')
class LogoutView(APIView):
    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": f"Hello {request.user.username}!"})

@method_decorator(csrf_exempt, name='dispatch')
class sessionLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return Response({"message": "Logged in successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        
class SessionLogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)

class CustomLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            tokens = get_tokens_for_user(user)
            return Response(tokens)
        raise AuthenticationFailed("Invalid credentials")

class cookieLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            tokens = get_tokens_for_user(user)
            response = Response({"message": "Login successful"}, status=status.HTTP_200_OK)
            response.set_cookie(
                key="access_token",
                value=str(tokens['access']),
                httponly=True,
                samesite="Lax",
                secure=False,
                max_age=300,
            )
            response.set_cookie(
                key="refresh_token",
                value=str(tokens['refresh']),
                httponly=True,
                samesite="Lax",
                secure=False,
                max_age=86400,
            )
            return response
        raise AuthenticationFailed("Invalid credentials")
    
class LogoutView1(APIView):
    def post(self, request):
        res = Response({"message": "Logged out"}, status=status.HTTP_200_OK)
        res.delete_cookie("access_token")
        res.delete_cookie("refresh_token")
        return res
