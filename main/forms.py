from django import forms
from django.contrib.auth.models import User
from .models import Movie, Review
from .validators import (
    fetch_and_validate_image_url,
    validate_movie_name,
    validate_description,
    validate_comment,
    validate_rating,
    validate_no_script_tag,
    MAX_DIRECTOR_LEN,
    MAX_CAST_LEN,
)


class RegisterForm(forms.ModelForm):
    email = forms.EmailField(required=True)
    # passwordInput widget hides value in DOM, 5.1
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        max_length=128,
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        max_length=128,
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def clean_username(self):
        # Username whitespace removed before unique check, 5.3
        username = self.cleaned_data.get('username', '').strip()
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError(
                'That username is already taken. Please choose another.'
            )
        return username

    def clean_email(self):
        # Email normalised to lowercase: Prevents duplicate accounts, 5.3
        return self.cleaned_data.get('email', '').lower().strip()

    def clean(self):
        cleaned_data = super().clean()
        p1 = cleaned_data.get('password1')
        p2 = cleaned_data.get('password2')
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError('Passwords do not match.')
        return cleaned_data

    def save(self, commit=True):
        # PBKDF2-SHA256 password hashing: Plaintext never stored, 5.1
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user


class LoginForm(forms.Form):
    # Max_length on LoginForm fields: Prevents oversized input DoS, 5.5
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={'autocomplete': 'username'}),
    )
    # passwordInput widget hides value in DOM, 5.1
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}),
        max_length=128,
    )


class MovieForm(forms.ModelForm):
    class Meta:
        model = Movie
        # created_by and modified_by excluded: Ownership spoofing prevented, 5.4 Access Control
        fields = ('name', 'director', 'cast', 'release_date', 'description', 'image')

    def clean_name(self):
        # Maximum sizes for data input + XSS defence, Section 8.1.2
        value = self.cleaned_data.get('name', '').strip()
        validate_movie_name(value)
        validate_no_script_tag(value)
        return value

    def clean_director(self):
        # Maximum sizes for data input + XSS defence, Section 8.1.2
        value = self.cleaned_data.get('director', '').strip()
        if len(value) > MAX_DIRECTOR_LEN:
            raise forms.ValidationError(
                f"Director name must not exceed {MAX_DIRECTOR_LEN} characters."
            )
        validate_no_script_tag(value)
        return value

    def clean_cast(self):
        # Maximum sizes for data input + XSS defence, Section 8.1.2
        value = self.cleaned_data.get('cast', '').strip()
        if len(value) > MAX_CAST_LEN:
            raise forms.ValidationError(
                f"Cast must not exceed {MAX_CAST_LEN} characters."
            )
        validate_no_script_tag(value)
        return value

    def clean_description(self):
        # Maximum sizes for data input + XSS defence, Section 8.1.2
        value = self.cleaned_data.get('description', '').strip()
        validate_description(value)
        validate_no_script_tag(value)
        return value

    def clean_image(self):
        # URL image validation, Section 8.1.2:
        # 1. Scheme must be http/https (deny javascript:, file://, etc.)
        # 2. Hostname must not resolve to private IP (SSRF prevention)
        # 3. Content must not exceed size limit (DoS prevention)
        # 4. Content must have valid image magic bytes
        #    (file extension and Content-Type NOT trusted - can be spoofed)
        url = self.cleaned_data.get('image')
        if url:
            fetch_and_validate_image_url(url)
        return url

    def clean_rating(self):
        # Server-side validation only: HTML min/max can be bypassed, Section 8.1.2
        rating = self.cleaned_data.get('rating')
        if rating is not None and not (1 <= rating <= 10):
            raise forms.ValidationError('Rating must be between 1 and 10.')
        return rating


class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        # created_by excluded: Ownership spoofing prevented, 5.4 Access Control
        fields = ('comment', 'rating')

    def clean_comment(self):
        # Maximum sizes for data input + XSS defence, Section 8.1.2
        value = self.cleaned_data.get('comment', '').strip()
        validate_comment(value)
        validate_no_script_tag(value)
        return value

    def clean_rating(self):
        # Server-side validation only: HTML min/max can be bypassed, Section 8.1.2
        rating = self.cleaned_data.get('rating')
        validate_rating(rating)
        return rating
