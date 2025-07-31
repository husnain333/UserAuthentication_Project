from django.urls import include, path
from django.urls import re_path
from rest_framework.urlpatterns import format_suffix_patterns
from .views import RootApiView, ApiRootWithCustomMetadata, ContentNegotiation, ApiRoot, NoNegotiationView, List1UserView, ListCacheTestView, ListUserNamespaceView, UserListUrlVersionaing , ListUserVersionView, ListUserView, RegisterView, LogoutView, ProtectedView, cursorPagination, redisHashView, sessionLoginView, SessionLogoutView, CustomLoginView, cookieLoginView, LogoutView1, RedisTestView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenObtainSlidingView, TokenRefreshSlidingView, TokenBlacklistView
from rest_framework_simplejwt.views import TokenVerifyView
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='login'),
    path('list/users/', ListUserView.as_view(), name='list_users'),
    path('list1/users/', List1UserView.as_view(), name='list1_users'),
    path('list/cursor/', cursorPagination.as_view(), name='cursor_pagination'),
    re_path(r'^(?P<version>(v1|v2))/users/$', UserListUrlVersionaing.as_view(), name='user-list'),
    path('list/namespace/', ListUserNamespaceView.as_view(), name='list_user_namespace'),
    path('list/version/', ListUserVersionView.as_view(), name='list_user_version'),
    path('verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('session-login/',sessionLoginView.as_view(), name='session_login'),
    path('session-logout/', SessionLogoutView.as_view(), name='session_logout'),
    path('custom-login/', CustomLoginView.as_view(), name='custom_login'),
    path('token/obtain/', TokenObtainSlidingView.as_view(), name='token_obtain_sliding'),
    path('token/refresh/', TokenRefreshSlidingView.as_view(), name='token_refresh_sliding'),
    path('token/blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('login/cookie/', cookieLoginView.as_view(), name='login_cookie'),
    path('logout/cookie/', LogoutView1.as_view(), name='logout_cookie'),
    path('redis/test/', RedisTestView.as_view(), name='redis_test'),
    path('list/cache/', ListCacheTestView.as_view(), name='list_cache'),
    path('hash/cache', redisHashView.as_view(), name='hash_view'),
    path('content/type', ContentNegotiation.as_view(), name='content_negotiation'),
    path('no/negotiation', NoNegotiationView.as_view(), name='no_negotiation'),
    path('meta/data', ApiRoot.as_view(), name='api_root'),
    path('custom/meta/data', ApiRootWithCustomMetadata.as_view(), name='custom_api_root'),
    path('reverse/url/', RootApiView.as_view(), name='api_root_view'),
]

urlpatterns = format_suffix_patterns(urlpatterns, allowed=['json', 'html', 'api','txt'])
