"""
URL configuration for moviereview project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
app_name = "main"

from django.urls import path
from . import views

urlpatterns = [
    # White: Public endpoints
    path('', views.home, name="home"),
    path('details/<int:id>/', views.details, name="details"),

    # Red: New public authentication endpoints, 5.3.2
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),

    # Yellow: User-only endpoints, 5.3.3
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),

    # Green: Modified endpoints, login required, 5.3.4
    path('addmovies/', views.add_movies, name="add_movies"),
    path('addreview/<int:id>/', views.add_review, name='add_review'),

    # Blue: Ownership-protected endpoints, 5.3.5
    path('movies/edit/<int:id>/', views.edit_movie, name='edit_movie'),
    path('movies/delete/<int:id>/', views.delete_movie, name='delete_movie'),
    path('reviews/edit/<int:id>/', views.edit_review, name='edit_review'),
    path('reviews/delete/<int:id>/', views.delete_review, name='delete_review'),
]

