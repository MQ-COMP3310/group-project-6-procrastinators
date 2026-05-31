from django.db import models
from django.contrib.auth.models import User


class AuditLog(models.Model):
    EVENT_CHOICES = [
        ('LOGIN_SUCCESS', 'Successful Login'),
        ('LOGIN_FAILED', 'Failed Login Attempt'),
        ('LOGOUT', 'Logout'),
        ('MOVIE_CREATE', 'Movie Created'),
        ('MOVIE_UPDATE', 'Movie Updated'),
        ('MOVIE_DELETE', 'Movie Deleted'),
        ('REVIEW_CREATE', 'Review Created'),
        ('REVIEW_UPDATE', 'Review Updated'),
        ('REVIEW_DELETE', 'Review Deleted'),
        ('AUTHZ_FAILED', 'Failed Authorization Attempt'),
        ('ADMIN_ACTION', 'Administrator Action'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    event_type = models.CharField(
        max_length=20,
        choices=EVENT_CHOICES,
        db_index=True
    )
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    outcome = models.CharField(
        max_length=10,
        choices=[('SUCCESS', 'Success'), ('FAILURE', 'Failure')]
    )
    affected_object_id = models.IntegerField(null=True, blank=True)
    affected_object_type = models.CharField(max_length=20, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    action_details = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise PermissionError('Audit logs cannot be modified (append-only)')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError('Audit logs cannot be deleted (immutable)')

    def __str__(self):
        return f"{self.get_event_type_display()} - {self.timestamp}"


class Movie(models.Model):
    # Fields for the movie table
    name = models.CharField(max_length=300)
    director = models.CharField(max_length=300)
    cast = models.CharField(max_length=300)
    release_date = models.DateField()
    description = models.TextField(max_length=5000)
    rating = models.FloatField(default=0)
    image = models.URLField(default=None, null=True)

    def __str__(self):
        return self.name

class Review(models.Model):
    movie = models.ForeignKey(Movie, on_delete=models.CASCADE)
    comment = models.TextField(max_length=1000, null=True)
    rating = models.FloatField(default=0)

    def __str__(self):
        return self.movie.name

