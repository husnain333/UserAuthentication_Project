from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth.models import User

class JWTAuthTests(APITestCase):
    def setUp(self):
        self.username = "husnain"
        self.password = "TestPass123!"
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password
        )
        

    def test_cookie_jwt_auth_flow(self):
        login_response = self.client.post("/api/auth/login/cookie/", {
            "username": self.username,
            "password": self.password
        }, format="json")

        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn("access_token", login_response.cookies) 

        protected_response = self.client.get("/api/auth/protected/")
        self.assertEqual(protected_response.status_code, status.HTTP_200_OK)
        self.assertEqual(protected_response.data["message"], f"Hello {self.username}!")
