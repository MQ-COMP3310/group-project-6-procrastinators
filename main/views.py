from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponseForbidden
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.views.decorators.http import require_http_methods, require_POST
from .models import Movie, Review, UserProfile
from .forms import MovieForm, ReviewForm, RegisterForm, LoginForm


# All permission decisions in one function, 5.4 Complete Mediation
# Authorisation always fails closed (returns False); Principle: Fail Secure
# is_staff AND adminRole checked separately; Principle: Separation of Privilege
def authorise_content_access(user, content):
    if not user.is_authenticated:
        return False
    try:
        if user.is_staff or user.profile.adminRole:
            return True
    except UserProfile.DoesNotExist:
        pass
    return content.created_by == user


@require_http_methods(['GET', 'POST'])
def register_view(request):
    if request.user.is_authenticated:
        return redirect('main:home')
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            # UserProfile created with adminRole=False on registration; Principle: Secure Defaults
            UserProfile.objects.create(user=user, adminRole=False)
            login(request, user)
            messages.success(request, 'Account created successfully.')
            return redirect('main:home')
    else:
        form = RegisterForm()
    return render(request, 'main/register.html', {'form': form})


@require_http_methods(['GET', 'POST'])
def login_view(request):
    if request.user.is_authenticated:
        return redirect('main:home')
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            try:
                user_obj = User.objects.get(username=username)
                profile = user_obj.profile
            except (User.DoesNotExist, UserProfile.DoesNotExist):
                # Generic error message: wrong password or wrong username, 5.5 Rate Limiting
                messages.error(request, 'Invalid username or password.')
                return render(request, 'main/login.html', {'form': form})

            # Lockout checked before authenticate() is called, 5.5 Rate Limiting
            if profile.is_locked_out():
                messages.error(request, 'Account temporarily locked. Please try again later.')
                return render(request, 'main/login.html', {'form': form})

            # authenticate() uses constant-time PBKDF2 comparison, 5.1
            user = authenticate(request, username=username, password=password)
            if user is not None:
                profile.reset_failed_attempts()
                # login() swaps session ID: Prevents session fixation, 5.5 Session Security
                login(request, user)
                next_url = request.POST.get('next', '')
                if next_url and next_url.startswith('/') and not next_url.startswith('//'):
                    return redirect(next_url)
                return redirect('main:home')
            else:
                # Failed attempt counter increased on bad credentials, 5.5 Rate Limiting
                profile.record_failed_attempt()
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    return render(request, 'main/login.html', {'form': form})


# @require_POST on logout: Rejects GET-based CSRF forced logout, 5.5 Session Security
# logout() flushes session and clears cookie server-side, 5.5 Session Security
@require_POST
@login_required
def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('main:home')


@login_required
@require_http_methods(['GET', 'POST'])
def profile_view(request):
    return render(request, 'main/profile.html', {'user': request.user})


def home(request):
    # ORM icontains uses parameterised query: no SQL injection, 5.3
    query = request.GET.get('title', '').strip()
    if query:
        all_movies = Movie.objects.filter(name__icontains=query)
    else:
        all_movies = Movie.objects.all()
    return render(request, 'main/index.html', {'movies': all_movies})


def details(request, id):
    # get_object_or_404: No DB error details leaked to client, 5.3
    movie = get_object_or_404(Movie, id=id)
    reviews = Review.objects.filter(movie=movie).order_by('-created_at')
    reviewed = False
    if request.user.is_authenticated:
        reviewed = Review.objects.filter(movie=movie, created_by=request.user).exists()
    return render(request, 'main/details.html', {
        'movie': movie,
        'reviews': reviews,
        'reviewed': reviewed,
    })


# created_by assigned from request.user server-side: Never from POST data, 5.4 Access Control
@login_required
@require_http_methods(['GET', 'POST'])
def add_movies(request):
    if request.method == 'POST':
        form = MovieForm(request.POST)
        if form.is_valid():
            movie = form.save(commit=False)
            movie.created_by = request.user
            movie.save()
            messages.success(request, 'Movie added successfully.')
            return redirect('main:details', id=movie.id)
    else:
        form = MovieForm()
    return render(request, 'main/addmovies.html', {'form': form})


# created_by assigned from request.user server-side: Never from POST data, 5.4 Access Control
@login_required
@require_http_methods(['GET', 'POST'])
def add_review(request, id):
    movie = get_object_or_404(Movie, id=id)
    if Review.objects.filter(movie=movie, created_by=request.user).exists():
        messages.warning(request, 'You have already reviewed this movie.')
        return redirect('main:details', id=id)
    if request.method == 'POST':
        form = ReviewForm(request.POST)
        if form.is_valid():
            review = form.save(commit=False)
            review.movie = movie
            review.created_by = request.user
            review.save()
            messages.success(request, 'Review submitted.')
            return redirect('main:details', id=id)
    else:
        form = ReviewForm()
    return render(request, 'main/details.html', {
        'movie': movie,
        'form': form,
        'reviews': Review.objects.filter(movie=movie).order_by('-created_at'),
    })


# authorise_content_access() called before any data is processed, 5.4
@login_required
@require_http_methods(['GET', 'POST'])
def edit_movie(request, id):
    movie = get_object_or_404(Movie, id=id)
    if not authorise_content_access(request.user, movie):
        return HttpResponseForbidden('Permission denied.')
    if request.method == 'POST':
        form = MovieForm(request.POST, instance=movie)
        if form.is_valid():
            updated = form.save(commit=False)
            updated.modified_by = request.user
            updated.save()
            messages.success(request, 'Movie updated.')
            return redirect('main:details', id=movie.id)
    else:
        form = MovieForm(instance=movie)
    return render(request, 'main/edit_movie.html', {'form': form, 'movie': movie})


# @require_POST: Delete actions use POST forms not GET links, 5.5 Session Security
@login_required
@require_POST
def delete_movie(request, id):
    movie = get_object_or_404(Movie, id=id)
    if not authorise_content_access(request.user, movie):
        return HttpResponseForbidden('Permission denied.')
    movie.delete()
    messages.success(request, 'Movie deleted.')
    return redirect('main:home')


# authorise_content_access() called before any data is processed, 5.4
@login_required
@require_http_methods(['GET', 'POST'])
def edit_review(request, id):
    review = get_object_or_404(Review, id=id)
    if not authorise_content_access(request.user, review):
        return HttpResponseForbidden('Permission denied.')
    if request.method == 'POST':
        form = ReviewForm(request.POST, instance=review)
        if form.is_valid():
            form.save()
            messages.success(request, 'Review updated.')
            return redirect('main:details', id=review.movie.id)
    else:
        form = ReviewForm(instance=review)
    return render(request, 'main/edit_review.html', {'form': form, 'review': review})


# @require_POST: Delete actions use POST forms not GET links, 5.5 Session Security
@login_required
@require_POST
def delete_review(request, id):
    review = get_object_or_404(Review, id=id)
    if not authorise_content_access(request.user, review):
        return HttpResponseForbidden('Permission denied.')
    movie_id = review.movie.id
    review.delete()
    messages.success(request, 'Review deleted.')
    return redirect('main:details', id=movie_id)
