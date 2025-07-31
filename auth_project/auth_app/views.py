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
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator
from django.core.cache import cache
from django_redis import get_redis_connection
import time
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.pagination import PageNumberPagination, CursorPagination
from rest_framework.versioning import QueryParameterVersioning, URLPathVersioning, NamespaceVersioning
from rest_framework.renderers import JSONRenderer, HTMLFormRenderer, TemplateHTMLRenderer, BrowsableAPIRenderer, OpenAPIRenderer
from .negotiation import IgnoreClientContentNegotiation
from rest_framework.metadata import SimpleMetadata
from rest_framework.reverse import reverse
from .authentication import CookieJWTAuthentication
from django.utils.timezone import now


class RootApiView(APIView):
    def get(self, request):
        year = now().year
        data = {
            'year-summary-url': reverse('year-summary', args=[year], request=request)
        }
        return Response(data)

class CustomMeta(SimpleMetadata):
    def determine_metadata(self, request, view):
        metadata = super().determine_metadata(request, view)
        metadata['note'] = "This is a custom note added to metadata."
        return metadata

class ApiRootWithCustomMetadata(APIView):
    metadata_class = CustomMeta
    permission_classes = [AllowAny]
    def get(self, request):
        return Response({"message": "Hello from DRF!"})

class ApiRoot(APIView):
    metadata_class = SimpleMetadata
    permission_classes = [AllowAny]
    def get(self, request):
        return Response({"message": "Hello from DRF!"})


class ContentNegotiation(APIView):
    permission_classes = [AllowAny]
    renderer_classes = [TemplateHTMLRenderer]
    def get(self, request):
        return Response({"message": "Hello from DRF!"}, template_name="auth_app/content_negotiation.html")

class NoNegotiationView(APIView):
    """
    An example view that does not perform content negotiation.
    """
    content_negotiation_class = IgnoreClientContentNegotiation

    def get(self, request, format=None):
        return Response({
            'accepted media type': request.accepted_renderer.media_type
        })

class ListUserNamespaceView(APIView):
    versioning_class = NamespaceVersioning
    permission_classes = [AllowAny]

    def get(self, request):
        if request.version == 'v1':
            data = [{"username": user.username} for user in User.objects.all()]
        elif request.version == 'v2':
            data = [{"username": user.username, "email": user.email} for user in User.objects.all()]
        else:
            return Response({"error": "Invalid version"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(data)

class ListUserVersionView(generics.ListAPIView):
    versioning_class = QueryParameterVersioning
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    
    def get(self, request):
        users = User.objects.all()
        if request.version == 'v1':
            data = [{"username": user.username} for user in users]
        elif request.version == 'v2':
            data = [{"username": user.username, "email": user.email} for user in users]
        return Response(data)

class UserListUrlVersionaing(APIView):
    versioning_class = URLPathVersioning
    permission_classes = [AllowAny]

    def get(self, request, version):
        users = User.objects.all()
        if version == 'v1':
            data = [{"username": user.username} for user in users]
        elif version == 'v2':
            data = [{"username": user.username, "email": user.email} for user in users]
        return Response(data)

class FunctionCacheTestView(APIView):
    def get(self, request):
        value = cache.get("my_key")
        if not value:
            value = "new data"
            cache.set("my_key", value, timeout=60)
            source = "Set to cache"
        else:
            source = "From cache"
        return Response({"data": value, "source": source})

class RedisTestView(APIView):
    def get(self, request):
        key = "hello"

        value = cache.get(key)
        if value:
            source = "Redis Cache"
        else:
            value = f"world at {time.time()}"
            cache.set(key, value, timeout=60)
            source = "Freshly Set"

        return Response({"message": value, "source": source})

class ListCacheTestView(APIView):
    cache_key = "list1"
    def get(self, request):
        data = cache.get(self.cache_key)
        if data:
            source = "From Redis cache"
        else:
            data = ["1", "2", "3"]
            cache.set(self.cache_key, data, timeout=300)
            source = "Set to Redis cache"
        return Response({"data": data, "source": source})
    
    def put(self, request):
        data = cache.get(self.cache_key)
        if not data:
            return Response({"error": "No data in cache. Please GET first."}, status=404)
        index = request.data.get("index")
        value = request.data.get("value")
        index = int(index)
        if index < 0 or index >= len(data):
            return Response({"error": "Index out of range."}, status=400)
        
        data[index] = value
        cache.set(self.cache_key, data, timeout=300)
        return Response({"message": "Value updated successfully.", "data": data})
    
    def post(self, request):
        newitem = request.data.get("new")
        if not newitem:
            return Response({"error": "No item provided."}, status=status.HTTP_400_BAD_REQUEST)

        data = cache.get(self.cache_key)
        if not data:
            return Response({"error": "No data in cache. Please GET first."}, status=404)

        data.append(newitem)
        cache.set(self.cache_key, data, timeout=300)

        return Response({"message": f"{newitem} added!", "updated_items": data})
    
    def delete(self, request):
        cache.delete(self.cache_key)
        return Response({"message": "Cache cleared successfully."})

class redisHashView(APIView):
    redisKey = "itemsHash"
    def get(self, request):
        r = get_redis_connection("default")
        data = r.hgetall(self.redisKey)

        decode = {k.decode(): v.decode() for k, v in data.items()}
        return Response(decode)
    
    def post(self, request):
        id = request.data.get("id")
        value = request.data.get("value")
        if not id or not value:
            return Response({"error": "ID and value are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        r = get_redis_connection("default")
        r.hset(self.redisKey, id, value)
        return Response({"message": f"Item {id} added with value {value}."})
    
    def delete(self, request):
        id = request.data.get("id")
        if not id:
            return Response({"error": "ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        r = get_redis_connection("default")
        r.hdel(self.redisKey, id)
        return Response({"message": f"Item {id} deleted."})


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

class MyCursorPagination(CursorPagination):
    page_size = 5
    ordering = '-username'

class cursorPagination(generics.ListAPIView):
    pagination_class = MyCursorPagination
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

class List1UserView(generics.ListAPIView):
    pagination_class = PageNumberPagination
    page_size = 5
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

class ListUserView(generics.ListAPIView):
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

@method_decorator(cache_page(30), name='dispatch')
class ProtectedView(APIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        import time
        current_time = time.time()
        return Response({"message": f"Hello {request.user.username}!", "time": current_time})

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
