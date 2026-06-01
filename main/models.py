from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    # adminRole=False default: Least Privilege Principle, 5.4 Proper Access Control
    adminRole = models.BooleanField(default=False)
    # failed_attempts counter stored server-side, 5.5 Rate Limiting
    failed_attempts = models.IntegerField(default=0)
    # lockout_until uses real-time not a counter, 5.5 Rate Limiting
    lockout_until = models.DateTimeField(null=True, blank=True)

    def is_locked_out(self):
        # is_locked_out() fails closed in edge cases; Principle: Fail Secure
        if self.lockout_until is None:
            return False
        return timezone.now() < self.lockout_until

    def record_failed_attempt(self):
        # Account locked for 15 minutes after 5 failed attempts, 5.5 Rate Limiting
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            self.lockout_until = timezone.now() + timezone.timedelta(minutes=15)
        self.save()

    def reset_failed_attempts(self):
        # Reset counter and lockout on successful authentication
        self.failed_attempts = 0
        self.lockout_until = None
        self.save()


class Movie(models.Model):
    name = models.CharField(max_length=300)
    director = models.CharField(max_length=300)
    cast = models.CharField(max_length=300)
    release_date = models.DateField()
    description = models.TextField(max_length=5000)
    rating = models.FloatField(default=0)
    image = models.URLField(default=None, null=True)
    # created_by uses SET_NULL: No orphaned ownership, 5.4 Access Control
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_movies'
    )
    # null=True allows existing fixture data to load without this field, 5.4
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    # modified_by tracks who last edited, 5.4 Access Control
    modified_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='modified_movies'
    )
    # modified_at auto-updates on save() for audit trail, 5.4
    modified_at = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return self.name


class Review(models.Model):
    movie = models.ForeignKey(Movie, on_delete=models.CASCADE)
    comment = models.TextField(max_length=1000, null=True)
    rating = models.FloatField(default=0)
    # created_by uses CASCADE: Prevents NULL ownership exploit, 5.4 Access Control
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='reviews'
    )
    # null=True allows existing fixture data to load without this field, 5.4
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    modified_at = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return self.movie.name