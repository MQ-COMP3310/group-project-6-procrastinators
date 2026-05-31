from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from datetime import date

from .models import Movie, Review, UserProfile


# Create your tests here.
class AuthenticationAuthorisationTests(TestCase):
    """
    Task 7b): Security tests for the authentication and authorisation mechanism
    
    These tests are for the Part 2 security requirements:
    - Users must be able to manage their own content.
    - Users must not be able to edit or delete content they did not create.
    - Administrators must be able to edit or delete any content.
    - Passwords must not be stored in plaintext.
    """
    
    def setUp(self):
        self.owner = User.objects.create_user(
            username="owner",
            password="ChooseStrongP@ssword123!"
        )
        
        self.other_user = User.objects.create_user(
            username="otheruser",
            password="ChooseStrongP@ssword123!"
        )
        
        self.admin_user = User.objects.create_user(
            username="admin",
            password="ChooseStrongP@ssword123!",
            is_staff=True,
            is_superuser=True
        )
        
        # Regular users have adminRole=False by default
        UserProfile.objects.create(user=self.owner, adminRole=False)
        UserProfile.objects.create(user=self.other_user, adminRole=False)
        UserProfile.objects.create(user=self.admin_user, adminRole=True)
        
        self.movie = Movie.objects.create(
            name="Test Movie",
            director="Test Director",
            cast="Test Cast",
            release_date=date(2000, 1, 1),
            description="Test Description",
            rating=8.0,
            image="https://example.com/test-image.jpg",
            created_by=self.owner
        )
        
        self.review = Review.objects.create(
            movie=self.movie,
            comment="Test Review",
            rating=7.0,
            created_by=self.owner
        )
        
    def test_password_not_stored_in_plaintext(self):
        """
        Requirement tested:
        Passwords must be securely hashed and must not be stored in plaintext.
        
        Expected result should show:
        The stored password value should not be the same as the raw password.
        """
        user = User.objects.create_user(
            username="testuser",
            password="ChooseStrongP@ssword123!"
        )    
        
        self.assertNotEqual(user.password, "ChooseStrongP@ssword123!")
        self.assertTrue(user.password.startswith("pbkdf2_sha256$"))
        
    def test_anonymous_user_cannot_add_movie(self):
        """
        Requirement tested:
        A user that is not logged in must not be able to add any content.
        
        Expected result should show:
        Anonymous user should be redirected to the login page or denied access.
        """
        url = reverse("main:add_movies")
        
        response = self.client.post(url, {
            "name": "Unauthorised Movie",
            "director": "Unknown", 
            "cast": "Unknown",
            "release_date": "2026-05-20",
            "description": "This should not be created.",
            "image": "https://example.com/not-good.jpg"
        })
        
        self.assertIn(response.status_code, [302, 403])
        self.assertFalse(Movie.objects.filter(name="Unauthorised Movie").exists())
        
    def test_owner_can_edit_their_own_movie(self):
        """
        Requirement tested:
        A user that is logged in must be able to manage their own content.
        
        Expected result should show:
        The owner can update their own movie.
        """
        self.client.login(username="owner", password="ChooseStrongP@ssword123!")
        
        url = reverse("main:edit_movie", args=[self.movie.id])
        
        response = self.client.post(url, {
            "name": "Updated Movie",
            "director": "Updated Director",
            "cast": "Updated Cast",
            "release_date": "2000-01-01",
            "description": "Updated description",
            "image": "https://example.com/updated.jpg"
        })
        
        self.movie.refresh_from_db()
        
        self.assertIn(response.status_code, [200, 302])
        self.assertEqual(self.movie.name, "Updated Movie")
        
    def test_non_owner_cannot_edit_another_users_movie(self):
        """
        Requirement tested:
        Users must not be able to edit content they did not create.
        
        Expected results should show:
        A non-owner receives HTTP 403 Forbidden and the movie remains unchanged.
        """
        self.client.login(username="otheruser", password="ChooseStrongP@ssword123!")
        url = reverse("main:edit_movie", args=[self.movie.id])
        response = self.client.post(url, {
            "name": "Malicious Update",
            "director": "Changed Director",
            "cast": "Changed Cast", 
            "release_date": "2000-01-01",
            "description": "This should not be saved.",
            "image": "https://example.com/changed.jpg"
        })    
        
        self.movie.refresh_from_db()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.movie.name, "Test Movie")
        
    def test_admin_can_edit_any_movie(self):
        """
        Requirement tested:
        Administrators must be able to edit any content.
        
        Expected result should show:
        Admin user can update a movie created by another user.
        """
        self.client.login(username="admin", password="ChooseStrongP@ssword123!")
        url = reverse("main:edit_movie", args=[self.movie.id])
        response = self.client.post(url, {
            "name": "Admin Updated Movie",
            "director": "Admin Director",
            "cast": "Admin Cast",
            "release_date": "2000-01-01",
            "description": "Admin update",
            "image": "https://example.com/admin.jpg"
        })
        
        self.movie.refresh_from_db()
        self.assertIn(response.status_code, [200, 302])
        self.assertEqual(self.movie.name, "Admin Updated Movie")
        
    def test_non_owner_cannot_delete_another_users_review(self):
        """
        Requirement tested:
        Users must not be able to delete reviews they did not create.
        
        Expected result should show:
        A non-owner receives HTTP 403 Forbidden and the review remains in the database.
        """
        self.client.login(username="otheruser", password="ChooseStrongP@ssword123!")
        url = reverse("main:delete_review", args=[self.review.id])
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Review.objects.filter(id=self.review.id).exists())
        
    def test_admin_can_delete_any_review(self):
        """
        Requirement tested:
        Admin must be able to delete any content.
        
        Expected result should show:
        Admin user can delete a review created by another user.
        """
        self.client.login(username="admin", password="ChooseStrongP@ssword123!")
        url = reverse("main:delete_review", args=[self.review.id])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [200, 302])
        self.assertFalse(Review.objects.filter(id=self.review.id).exists())
        
    def test_non_owner_cannot_delete_another_users_movie(self):
        """
        Requirement tested:
        Users must not be able to delete movies they did not create.
        
        Expected result should show:
        A non-owner receives HTTP 403 Forbidden and the movie remains in the database.
        """
        self.client.login(username="otheruser", password="ChooseStrongP@ssword123!")
        url = reverse("main:delete_movie", args=[self.movie.id])
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Movie.objects.filter(id=self.movie.id).exists())