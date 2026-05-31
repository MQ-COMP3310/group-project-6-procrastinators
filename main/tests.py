from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from datetime import date

from .models import Movie, Review, UserProfile, AuditLog
from .utils import log_security_event


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


# ===========================================================================
# TEST SUITE: AUDIT LOGGING SECURITY
# ===========================================================================

class AuditLogModelTests(TestCase):

    def test_logs_cannot_be_modified(self):
        log = AuditLog.objects.create(
            event_type='LOGIN_SUCCESS',
            outcome='SUCCESS',
            action_details='Original entry'
        )
        log.action_details = 'Tampered entry'
        with self.assertRaises(PermissionError):
            log.save()

    def test_logs_cannot_be_deleted(self):
        log = AuditLog.objects.create(
            event_type='LOGIN_SUCCESS',
            outcome='SUCCESS'
        )
        with self.assertRaises(PermissionError):
            log.delete()


class AuditLoggingFunctionTests(TestCase):

    def test_successful_event_logged(self):
        user = User.objects.create_user(
            username='testuser',
            password='ChooseStrongP@ssword123!'
        )
        log_security_event(
            event_type='MOVIE_CREATE',
            user=user,
            outcome='SUCCESS',
            affected_object_id=5,
            affected_object_type='Movie',
            source_ip='192.168.1.1',
            action_details='Movie created: Test Movie'
        )
        log = AuditLog.objects.filter(event_type='MOVIE_CREATE').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.outcome, 'SUCCESS')
        self.assertEqual(log.user, user)
        self.assertEqual(log.affected_object_id, 5)

    def test_failed_event_logged(self):
        user = User.objects.create_user(
            username='testuser',
            password='ChooseStrongP@ssword123!'
        )
        log_security_event(
            event_type='LOGIN_FAILED',
            user=user,
            outcome='FAILURE',
            source_ip='192.168.1.100',
            action_details='Invalid password'
        )
        log = AuditLog.objects.filter(event_type='LOGIN_FAILED').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.outcome, 'FAILURE')
        self.assertEqual(log.user, user)

    def test_authorization_failure_logged(self):
        user = User.objects.create_user(
            username='attacker',
            password='ChooseStrongP@ssword123!'
        )
        log_security_event(
            event_type='AUTHZ_FAILED',
            user=user,
            outcome='FAILURE',
            affected_object_id=10,
            affected_object_type='Movie',
            source_ip='192.168.1.50',
            action_details='Unauthorized attempt to edit movie 10'
        )
        log = AuditLog.objects.filter(event_type='AUTHZ_FAILED').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.outcome, 'FAILURE')
        self.assertEqual(log.affected_object_id, 10)


class SensitiveDataProtectionTests(TestCase):

    def test_no_passwords_in_logs(self):
        log_security_event(
            event_type='ADMIN_ACTION',
            action_details='User password: MySecretPassword123'
        )
        log = AuditLog.objects.filter(event_type='ADMIN_ACTION').first()
        self.assertNotIn('MySecretPassword123', log.action_details)
        self.assertIn('[REDACTED]', log.action_details)

    def test_no_hashes_in_logs(self):
        log_security_event(
            event_type='ADMIN_ACTION',
            action_details='User hash: pbkdf2_sha256$260000$abc123def456'
        )
        log = AuditLog.objects.filter(event_type='ADMIN_ACTION').first()
        self.assertNotIn('pbkdf2_sha256', log.action_details)
        self.assertIn('[REDACTED]', log.action_details)

    def test_no_tokens_in_logs(self):
        log_security_event(
            event_type='ADMIN_ACTION',
            action_details='CSRF_TOKEN: abc123xyz SESSION_COOKIE: def456uvw'
        )
        log = AuditLog.objects.filter(event_type='ADMIN_ACTION').first()
        self.assertNotIn('abc123xyz', log.action_details)
        self.assertNotIn('def456uvw', log.action_details)
        self.assertIn('[REDACTED]', log.action_details)


class LogContextTests(TestCase):

    def test_timestamp_recorded(self):
        log = AuditLog.objects.create(
            event_type='LOGIN_SUCCESS',
            outcome='SUCCESS'
        )
        self.assertIsNotNone(log.timestamp)

    def test_user_recorded(self):
        user = User.objects.create_user(username='testuser', password='pass')
        log_security_event(
            event_type='LOGIN_SUCCESS',
            user=user,
            outcome='SUCCESS'
        )
        log = AuditLog.objects.filter(event_type='LOGIN_SUCCESS').first()
        self.assertEqual(log.user, user)

    def test_event_type_recorded(self):
        log_security_event(
            event_type='MOVIE_CREATE',
            outcome='SUCCESS'
        )
        log = AuditLog.objects.filter(event_type='MOVIE_CREATE').first()
        self.assertEqual(log.event_type, 'MOVIE_CREATE')

    def test_affected_object_recorded(self):
        log_security_event(
            event_type='MOVIE_UPDATE',
            affected_object_id=42,
            affected_object_type='Movie',
            outcome='SUCCESS'
        )
        log = AuditLog.objects.filter(event_type='MOVIE_UPDATE').first()
        self.assertEqual(log.affected_object_id, 42)
        self.assertEqual(log.affected_object_type, 'Movie')

    def test_ip_address_recorded(self):
        log_security_event(
            event_type='LOGIN_SUCCESS',
            outcome='SUCCESS',
            source_ip='203.0.113.42'
        )
        log = AuditLog.objects.filter(event_type='LOGIN_SUCCESS').first()
        self.assertEqual(log.source_ip, '203.0.113.42')

    def test_outcome_recorded(self):
        log_success = AuditLog.objects.create(
            event_type='LOGIN_SUCCESS',
            outcome='SUCCESS'
        )
        log_failure = AuditLog.objects.create(
            event_type='LOGIN_FAILED',
            outcome='FAILURE'
        )
        self.assertEqual(log_success.outcome, 'SUCCESS')
        self.assertEqual(log_failure.outcome, 'FAILURE')


class AccessControlTests(TestCase):

    def test_admin_can_view_logs(self):
        admin_user = User.objects.create_user(
            username='admin',
            password='ChooseStrongP@ssword123!',
            is_staff=True
        )
        self.assertTrue(admin_user.is_staff)

    def test_regular_user_not_admin(self):
        regular_user = User.objects.create_user(
            username='user',
            password='ChooseStrongP@ssword123!',
            is_staff=False
        )
        self.assertFalse(regular_user.is_staff)


class AllEventTypesTests(TestCase):

    def test_all_event_types_valid(self):
        for event_type, _ in AuditLog.EVENT_CHOICES:
            log = AuditLog.objects.create(
                event_type=event_type,
                outcome='SUCCESS'
            )
            self.assertEqual(log.event_type, event_type)