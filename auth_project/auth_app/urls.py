from django.urls import path
from .views import RegisterView, LogoutView, ProtectedView, sessionLoginView, SessionLogoutView, CustomLoginView, cookieLoginView, LogoutView1
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenObtainSlidingView, TokenRefreshSlidingView, TokenBlacklistView
from rest_framework_simplejwt.views import TokenVerifyView
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='login'),
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
]
