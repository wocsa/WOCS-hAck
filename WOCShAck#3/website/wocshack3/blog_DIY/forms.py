from django import forms
from .models import UserProfile, Tutorial, Comment
from django.core.validators import FileExtensionValidator


class LoginForm(forms.Form):
    username = forms.CharField(max_length=63, widget=forms.TextInput(attrs={'placeholder': 'Username', 'class': 'form-control'}))
    password = forms.CharField(max_length=63, widget=forms.PasswordInput(attrs={'placeholder': 'Password', 'class': 'form-control'}))
    authorize = forms.BooleanField(required=False, label='Authorize Actions Logging')



class RegisterForm(forms.Form):
    username = forms.CharField(max_length=63, widget=forms.TextInput(attrs={'placeholder': 'Username', 'class': 'form-control'}))
    email = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Email', 'class': 'form-control'}))
    password = forms.CharField(max_length=63, widget=forms.PasswordInput(attrs={'placeholder': 'Password', 'class': 'form-control'}))
    confirm_password = forms.CharField(max_length=63, widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password', 'class': 'form-control'}))
    authorize = forms.BooleanField(required=False, label='Authorize Actions Logging')


class UserProfileForm(forms.ModelForm):
    new_email = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Username', 'class': 'form-control'}))
    class Meta:
        model = UserProfile
        fields = ['profile_picture', 'bio']
        widgets = {
            'profile_picture': forms.FileInput(attrs={'accept':'image/*','class': 'form-control'}),
            'bio': forms.Textarea(attrs={'placeholder': 'Bio', 'class': 'form-control'})
        }
        validators = [FileExtensionValidator(['jpg', 'png', 'jpeg', 'gif'])]


class ChangePasswordForm(forms.Form):
    old_password = forms.CharField(max_length=63, widget=forms.PasswordInput(attrs={'placeholder': 'Old Password', 'class': 'form-control'}), label='Old Password')
    new_password = forms.CharField(max_length=63, widget=forms.PasswordInput(attrs={'placeholder': 'New Password', 'class': 'form-control'}), label='New Password')
    confirm_new_password = forms.CharField(max_length=63, widget=forms.PasswordInput(attrs={'placeholder': 'Confirm New Password', 'class': 'form-control'}), label='Confirm New Password')


class ResetPasswordForm(forms.Form):
    username = forms.CharField(max_length=63, label='Username', widget=forms.TextInput(attrs={'placeholder': 'Username', 'class': 'form-control'}))

class ResetOldPasswordForm(forms.Form):
    new_password = forms.CharField(max_length=63, widget=forms.PasswordInput(attrs={'placeholder': 'New Password', 'class': 'form-control'}), label='New Password')
    confirm_new_password = forms.CharField(max_length=63, widget=forms.PasswordInput(attrs={'placeholder': 'Confirm New Password', 'class': 'form-control'}), label='Confirm New Password')


class TutorialForm(forms.ModelForm):
    class Meta:
        model = Tutorial
        fields = ['title']
        widgets = {
            'title': forms.TextInput(attrs={'placeholder': 'Title', 'class': 'form-control','required':'True'}),
        }


class AddContentForm(forms.Form):
    bodyline = forms.CharField(
        max_length=8000,
        widget=forms.Textarea(attrs={'placeholder': 'Text Content', 'class': 'form-control', 'rows': 5, 'cols': 40,'required':'True'}),
        label='Step description',
    )
    picture = forms.ImageField(
        widget=(forms.FileInput(attrs={'accept':'image/*','class': 'form-control','required':'True'})),
        label='Step picture',
    )


class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['bodyline']
        widgets = {
            'bodyline': forms.Textarea(attrs={'placeholder': 'Comment', 'class': 'form-control', 'rows': 2, 'cols': 40}),
        }
