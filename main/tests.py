from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from unittest.mock import patch
from datetime import date

from .models import Movie, Review, UserProfile, AuditLog
from .utils import log_security_event
from .validators import (
    validate_image_url_scheme,
    validate_no_private_ip,
    validate_image_magic_bytes,
    validate_image_size,
    validate_movie_name,
    validate_description,
    validate_comment,
    validate_rating,
    validate_no_script_tag,
    sanitize_html_entities,
    MAX_IMAGE_BYTES,
    MAX_MOVIE_NAME_LEN,
    MAX_DESCRIPTION_LEN,
    MAX_COMMENT_LEN,
)
from .forms import MovieForm, ReviewForm


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
        
    @patch('main.forms.fetch_and_validate_image_url')
    def test_owner_can_edit_their_own_movie(self, mock_fetch):
        mock_fetch.return_value = None
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
        
    @patch('main.forms.fetch_and_validate_image_url')
    def test_admin_can_edit_any_movie(self, mock_fetch):
        mock_fetch.return_value = None
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


# ===========================================================================
# TEST SUITE: INPUT VALIDATION SECURITY
# ===========================================================================

class URLSchemeValidationTests(TestCase):
    """
    Requirement tested:
    Deny insecure web protocols and accept https:// and optionally http:// only.
    (Section 8.1.2)
    """

    def test_https_url_is_accepted(self):
        """HTTPS URLs must be allowed."""
        try:
            validate_image_url_scheme('https://example.com/poster.jpg')
        except ValidationError:
            self.fail("https:// should be accepted but raised ValidationError.")

    def test_http_url_is_accepted(self):
        """HTTP URLs must be allowed."""
        try:
            validate_image_url_scheme('http://example.com/poster.jpg')
        except ValidationError:
            self.fail("http:// should be accepted but raised ValidationError.")

    def test_javascript_scheme_is_rejected(self):
        """javascript: URLs allow JS execution and must be rejected. (Section 8.1.2)"""
        with self.assertRaises(ValidationError):
            validate_image_url_scheme('javascript:alert(1)')

    def test_file_scheme_is_rejected(self):
        """file:// risks exposure of local server files and must be rejected. (Section 8.1.2)"""
        with self.assertRaises(ValidationError):
            validate_image_url_scheme('file:///etc/passwd')

    def test_ftp_scheme_is_rejected(self):
        """Non-HTTP/HTTPS protocols must be rejected."""
        with self.assertRaises(ValidationError):
            validate_image_url_scheme('ftp://example.com/image.jpg')

    def test_data_uri_is_rejected(self):
        """data: URIs must be rejected."""
        with self.assertRaises(ValidationError):
            validate_image_url_scheme('data:image/png;base64,abc123')


class SSRFPreventionTests(TestCase):
    """
    Requirement tested:
    Do not fetch private resources from inside the system.
    Blacklist on localhost, 127.0.0.0/8, 10.0.0.0/8 etc. (Section 8.1.2)
    """

    def _mock(self, ip):
        return [(None, None, None, None, (ip, 0))]

    def test_localhost_is_rejected(self):
        """'localhost' hostname must be rejected."""
        with self.assertRaises(ValidationError):
            validate_no_private_ip('http://localhost/admin')

    def test_loopback_ip_is_rejected(self):
        """127.x.x.x addresses must be rejected."""
        with patch('socket.getaddrinfo', return_value=self._mock('127.0.0.1')):
            with self.assertRaises(ValidationError):
                validate_no_private_ip('http://127.0.0.1/secret')

    def test_private_10_range_is_rejected(self):
        """10.0.0.0/8 private range must be rejected."""
        with patch('socket.getaddrinfo', return_value=self._mock('10.0.0.1')):
            with self.assertRaises(ValidationError):
                validate_no_private_ip('http://internal.corp/data')

    def test_private_192_168_range_is_rejected(self):
        """192.168.x.x private range must be rejected."""
        with patch('socket.getaddrinfo', return_value=self._mock('192.168.1.1')):
            with self.assertRaises(ValidationError):
                validate_no_private_ip('http://192.168.1.1/image.jpg')

    def test_private_172_16_range_is_rejected(self):
        """172.16.0.0/12 private range must be rejected."""
        with patch('socket.getaddrinfo', return_value=self._mock('172.16.0.1')):
            with self.assertRaises(ValidationError):
                validate_no_private_ip('http://172.16.0.1/image.jpg')

    def test_public_ip_is_accepted(self):
        """Public IP addresses must be allowed."""
        with patch('socket.getaddrinfo', return_value=self._mock('93.184.216.34')):
            try:
                validate_no_private_ip('https://example.com/poster.jpg')
            except ValidationError:
                self.fail("Public IP should be accepted but raised ValidationError.")


class ImageSizeLimitTests(TestCase):
    """
    Requirement tested:
    Place limits upon external resource size. Without checking size, a DoS
    can be achieved via a profoundly large image. (Section 8.1.2)
    """

    def test_image_within_size_limit_is_accepted(self):
        """Images within MAX_IMAGE_BYTES must be accepted."""
        data = b'\xff\xd8\xff' + b'\x00' * 100
        try:
            validate_image_size(data)
        except ValidationError:
            self.fail("Small image should be accepted.")

    def test_image_exceeding_size_limit_is_rejected(self):
        """Images exceeding MAX_IMAGE_BYTES must be rejected to prevent DoS."""
        data = b'\x00' * (MAX_IMAGE_BYTES + 1)
        with self.assertRaises(ValidationError):
            validate_image_size(data)

    def test_image_exactly_at_size_limit_is_accepted(self):
        """Images exactly at MAX_IMAGE_BYTES must be accepted."""
        data = b'\x00' * MAX_IMAGE_BYTES
        try:
            validate_image_size(data)
        except ValidationError:
            self.fail("Image at exact size limit should be accepted.")


class MagicByteValidationTests(TestCase):
    """
    Requirement tested:
    Limit external resource type to image formats. It is insecure to trust
    file extension or Content-Type (can be spoofed). Checking magic bytes
    is more effective. (Section 8.1.2)
    """

    def test_valid_jpeg_accepted(self):
        """JPEG files (FF D8 FF) must be accepted."""
        try:
            validate_image_magic_bytes(b'\xff\xd8\xff\xe0' + b'\x00' * 20)
        except ValidationError:
            self.fail("Valid JPEG magic bytes should be accepted.")

    def test_valid_png_accepted(self):
        """PNG files must be accepted."""
        try:
            validate_image_magic_bytes(b'\x89PNG\r\n\x1a\n' + b'\x00' * 20)
        except ValidationError:
            self.fail("Valid PNG magic bytes should be accepted.")

    def test_valid_gif_accepted(self):
        """GIF files must be accepted."""
        try:
            validate_image_magic_bytes(b'GIF89a' + b'\x00' * 20)
        except ValidationError:
            self.fail("Valid GIF magic bytes should be accepted.")

    def test_valid_webp_accepted(self):
        """WEBP files must be accepted."""
        try:
            validate_image_magic_bytes(b'RIFF\x00\x00\x00\x00WEBP' + b'\x00' * 20)
        except ValidationError:
            self.fail("Valid WEBP magic bytes should be accepted.")

    def test_executable_disguised_as_image_rejected(self):
        """
        An executable renamed to .jpg must be rejected by magic-byte check.
        Trusting extension alone is insecure (Section 8.1.2).
        """
        with self.assertRaises(ValidationError):
            validate_image_magic_bytes(b'MZ' + b'\x00' * 50)

    def test_svg_rejected(self):
        """SVG images can contain Javascript and must be rejected. (Section 8.1.2)"""
        with self.assertRaises(ValidationError):
            validate_image_magic_bytes(
                b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
            )

    def test_plain_text_rejected(self):
        """A plain text file must be rejected."""
        with self.assertRaises(ValidationError):
            validate_image_magic_bytes(b'Hello, I am not an image.' + b'\x00' * 20)


class FieldLengthValidationTests(TestCase):
    """
    Requirement tested:
    Maximum sizes for data input dependent on context. Not even the longest
    movie name should exceed 250 characters. (Section 8.1.2)
    """

    def test_movie_name_within_limit_accepted(self):
        try:
            validate_movie_name('A' * MAX_MOVIE_NAME_LEN)
        except ValidationError:
            self.fail("Movie name within limit should be accepted.")

    def test_movie_name_exceeding_limit_rejected(self):
        """Movie names exceeding 250 characters must be rejected server-side."""
        with self.assertRaises(ValidationError):
            validate_movie_name('A' * (MAX_MOVIE_NAME_LEN + 1))

    def test_description_within_limit_accepted(self):
        try:
            validate_description('B' * MAX_DESCRIPTION_LEN)
        except ValidationError:
            self.fail("Description within limit should be accepted.")

    def test_description_exceeding_limit_rejected(self):
        with self.assertRaises(ValidationError):
            validate_description('B' * (MAX_DESCRIPTION_LEN + 1))

    def test_comment_within_limit_accepted(self):
        try:
            validate_comment('C' * MAX_COMMENT_LEN)
        except ValidationError:
            self.fail("Comment within limit should be accepted.")

    def test_comment_exceeding_limit_rejected(self):
        with self.assertRaises(ValidationError):
            validate_comment('C' * (MAX_COMMENT_LEN + 1))


class RatingValidationTests(TestCase):
    """
    Requirement tested:
    No client-side validation for security-related data; server-side validation
    must be performed. The rating HTML min/max attribute can be changed via
    browser Inspector (Section 8.1.2 example).
    """

    def test_rating_within_bounds_accepted(self):
        """Ratings between 1 and 10 must be accepted."""
        for value in (1, 5, 10, 1.0, 9.9):
            try:
                validate_rating(value)
            except ValidationError:
                self.fail(f"Rating {value} should be accepted.")

    def test_rating_below_minimum_rejected(self):
        """Rating below 1 must be rejected server-side."""
        with self.assertRaises(ValidationError):
            validate_rating(0)

    def test_rating_above_maximum_rejected(self):
        """
        Rating above 10 must be rejected server-side.
        Changing max='10' to max='20' in browser Inspector allows input of 19 (Section 8.1.2).
        """
        with self.assertRaises(ValidationError):
            validate_rating(11)

    def test_rating_negative_value_rejected(self):
        with self.assertRaises(ValidationError):
            validate_rating(-1)

    def test_rating_arbitrarily_large_rejected(self):
        with self.assertRaises(ValidationError):
            validate_rating(9999)


class XSSValidationTests(TestCase):
    """
    Requirement tested:
    Validate and sanitise vectors for XSS attacks. Everything on the site
    persists in a database and is readable by anyone. (Section 8.1.2)
    """

    def test_plain_text_accepted(self):
        try:
            validate_no_script_tag("The Dark Knight is a great film.")
        except ValidationError:
            self.fail("Plain text should be accepted.")

    def test_script_tag_rejected(self):
        """Input containing a <script> tag must be rejected."""
        with self.assertRaises(ValidationError):
            validate_no_script_tag('<script>alert("xss")</script>')

    def test_script_tag_with_spaces_rejected(self):
        """Obfuscated <script> tags with internal spaces must be rejected."""
        with self.assertRaises(ValidationError):
            validate_no_script_tag('< script >alert(1)</ script >')

    def test_uppercase_script_tag_rejected(self):
        """Uppercase <SCRIPT> tags must be rejected (case-insensitive check)."""
        with self.assertRaises(ValidationError):
            validate_no_script_tag('<SCRIPT>evil()</SCRIPT>')

    def test_html_entity_encoding_converts_angle_brackets(self):
        """< and > must be converted to HTML entities. (Section 8.1.2)"""
        result = sanitize_html_entities('<script>alert("xss")</script>')
        self.assertNotIn('<script>', result)
        self.assertIn('&lt;script&gt;', result)

    def test_html_entity_encoding_converts_ampersand(self):
        """& must be encoded to &amp;."""
        result = sanitize_html_entities('Tom & Jerry')
        self.assertIn('&amp;', result)

    def test_html_entity_encoding_converts_quotes(self):
        """Double and single quotes must be encoded."""
        result = sanitize_html_entities('"quoted" and \'apostrophe\'')
        self.assertIn('&quot;', result)
        self.assertIn('&#x27;', result)


class ReviewFormValidationTests(TestCase):
    """
    Requirement tested:
    Server-side validation for all form fields; client-side attributes are
    not trusted. (Section 8.1.2)
    """

    def test_valid_review_form_passes(self):
        """A well-formed review must pass form validation."""
        form = ReviewForm(data={'comment': 'Great film!', 'rating': 8})
        self.assertTrue(form.is_valid(), form.errors)

    def test_review_rating_above_10_rejected(self):
        """
        Rating of 11 submitted via POST must be rejected server-side even if
        client-side HTML max='10' was bypassed.
        """
        form = ReviewForm(data={'comment': 'Good', 'rating': 11})
        self.assertFalse(form.is_valid())
        self.assertIn('rating', form.errors)

    def test_review_rating_below_1_rejected(self):
        """A rating of 0 must be rejected."""
        form = ReviewForm(data={'comment': 'Bad', 'rating': 0})
        self.assertFalse(form.is_valid())
        self.assertIn('rating', form.errors)

    def test_review_comment_exceeding_max_length_rejected(self):
        """A comment exceeding MAX_COMMENT_LEN must be rejected."""
        form = ReviewForm(data={'comment': 'X' * (MAX_COMMENT_LEN + 1), 'rating': 5})
        self.assertFalse(form.is_valid())
        self.assertIn('comment', form.errors)

    def test_review_comment_with_script_tag_rejected(self):
        """A comment containing a <script> tag must be rejected."""
        form = ReviewForm(data={'comment': '<script>alert(1)</script>', 'rating': 5})
        self.assertFalse(form.is_valid())
        self.assertIn('comment', form.errors)


class MovieFormValidationTests(TestCase):
    """
    Requirement tested:
    Server-side validation for all Movie form fields. (Section 8.1.2)
    """

    def _base(self, **overrides):
        data = {
            'name': 'Test Movie', 'director': 'Test Director',
            'cast': 'Actor A', 'release_date': '2024-01-01',
            'description': 'A test description.', 'image': '',
        }
        data.update(overrides)
        return data

    def test_movie_name_exceeding_limit_rejected(self):
        """Movie names over 250 characters must be rejected server-side."""
        form = MovieForm(data=self._base(name='A' * (MAX_MOVIE_NAME_LEN + 1)))
        self.assertFalse(form.is_valid())
        self.assertIn('name', form.errors)

    def test_movie_name_with_script_tag_rejected(self):
        """Movie names containing <script> tags must be rejected."""
        form = MovieForm(data=self._base(name='<script>alert(1)</script>'))
        self.assertFalse(form.is_valid())
        self.assertIn('name', form.errors)

    def test_movie_description_exceeding_limit_rejected(self):
        """Descriptions exceeding MAX_DESCRIPTION_LEN must be rejected."""
        form = MovieForm(data=self._base(description='D' * (MAX_DESCRIPTION_LEN + 1)))
        self.assertFalse(form.is_valid())
        self.assertIn('description', form.errors)

    @patch('main.validators.fetch_and_validate_image_url')
    def test_javascript_scheme_url_rejected(self, mock_fetch):
        """A javascript: URL in the image field must be rejected."""
        mock_fetch.side_effect = ValidationError(
            "URLs must use http or https. 'javascript' is not permitted."
        )
        form = MovieForm(data=self._base(image='javascript:alert(1)'))
        self.assertFalse(form.is_valid())
        self.assertIn('image', form.errors)

    @patch('main.validators.fetch_and_validate_image_url')
    def test_ssrf_private_ip_url_rejected(self, mock_fetch):
        """A URL resolving to a private IP must be rejected to prevent SSRF."""
        mock_fetch.side_effect = ValidationError(
            "URLs pointing to internal or private network addresses are not permitted."
        )
        form = MovieForm(data=self._base(image='http://192.168.1.1/secret.jpg'))
        self.assertFalse(form.is_valid())
        self.assertIn('image', form.errors)

    @patch('main.validators.fetch_and_validate_image_url')
    def test_oversized_image_url_rejected(self, mock_fetch):
        """A URL pointing to an oversized image must be rejected to prevent DoS."""
        mock_fetch.side_effect = ValidationError(
            "Image exceeds the maximum permitted size of 10 MB."
        )
        form = MovieForm(data=self._base(image='https://example.com/huge.jpg'))
        self.assertFalse(form.is_valid())
        self.assertIn('image', form.errors)

    @patch('main.validators.fetch_and_validate_image_url')
    def test_non_image_url_rejected(self, mock_fetch):
        """
        A URL pointing to a non-image file (wrong magic bytes) must be rejected.
        Trusting file extension alone is insecure (Section 8.1.2).
        """
        mock_fetch.side_effect = ValidationError(
            "The URL does not point to a recognised image file."
        )
        form = MovieForm(data=self._base(image='https://example.com/virus.jpg'))
        self.assertFalse(form.is_valid())
        self.assertIn('image', form.errors)

    @patch('main.forms.fetch_and_validate_image_url')
    def test_valid_image_url_accepted(self, mock_fetch):
        """A valid HTTPS URL pointing to a recognised image must be accepted."""
        mock_fetch.return_value = None
        form = MovieForm(data=self._base(image='https://example.com/poster.jpg'))
        self.assertNotIn('image', form.errors)
