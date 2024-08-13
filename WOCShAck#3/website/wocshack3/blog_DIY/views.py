from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.forms import formset_factory
from django.template import engines
from django.db import connection
from django.conf import settings
from django.db import IntegrityError
from rest_framework_simplejwt.tokens import RefreshToken
from lxml import etree
from . import forms, models
from .authentication import is_valid_token, is_authenticated, redirect_non_admin_user, retrieve_token, \
    redirect_invalid_user, retrieve_user_from_token, is_valid_email, is_valid_password, verif_admin, custom_redirect
import hashlib, jwt, pickle, base64, os
from .logs_manager import log_user_activity, get_logs, Logs
from .models import UserProfile

@log_user_activity("home")
def home(request):
    """
    Render the home page.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponse: The rendered home page.
    """
    return render(
        request=request,
        template_name="blog_DIY/home.html",
        context={
            "is_authenticated": is_authenticated(request),
            "is_admin": verif_admin(request)
        }
    )



@log_user_activity("login")
def login_user(request):
    """
    Handle user login.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponse: The login page response.
    """
    # Initialize form, message, and flags
    login_form = forms.LoginForm()
    message = ''
    successful_auth = False
    response = HttpResponse()
    logs = get_logs(request)

    # Check if user is already logged in
    if 'jwt_token' in request.COOKIES:
        token = request.COOKIES['jwt_token']
        if is_valid_token(token):
            # Get user information from the token
            decoded_token = jwt_decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=decoded_token['user_id'])
            message = f'You are already connected as {user.username}'
            # Redirect to home page
            return custom_redirect(request, response, '/', message)

    # Process login form submission
    if request.method == 'POST':
        login_form = forms.LoginForm(request.POST)
        if login_form.is_valid():
            # Check if user checked the authorization box
            if login_form.cleaned_data['authorize']:
                logs.log = True
            # Authenticate user
            user = authenticate(
                username=login_form.cleaned_data['username'],
                password=login_form.cleaned_data['password'],
            )
            if user is not None:
                # Generate a new JWT token for the user
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                # Set JWT token in cookies
                response.set_cookie(key='jwt_token', value=access_token, httponly=True)
                message = f'Hello, {user.username}! You are connected.'
                successful_auth = True
                logs.username = user.username
            else:
                message = 'Invalid credentials.'

    # Encode and set logs cookie
    logs = base64.b64encode(pickle.dumps(logs))
    logs = logs.decode('utf-8')
    response.set_cookie(key='logs', value=logs, httponly=True)

    # Render login template with form, message, and authentication status
    template_content = render(request, 'blog_DIY/login.html', {'login_form': login_form, 'message': message, 'is_authenticated': is_authenticated(request)})
    response.content = template_content.content

    # If authentication was successful, redirect to home page
    if successful_auth:
        response.status_code = 302
        response['Location'] = '/'
    return response




@log_user_activity("logout")
def logout_user(request):
    """
    Handle user logout.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponse: The logout redirect response.
    """
    response = HttpResponse()
    # Delete JWT token, logs, and CSRF token cookies
    if "jwt_token" in request.COOKIES:
        response.delete_cookie("jwt_token")
    if "logs" in request.COOKIES:
        response.delete_cookie("logs")
    if "csrftoken" in request.COOKIES:
        response.delete_cookie("csrftoken")
    # Redirect to login page with logout message
    return custom_redirect(
        request=request,
        response=response,
        location="/login",
        message=f"{get_logs(request).username} logged out"
    )



@log_user_activity("register_user")
def register_user(request):
    """
    Handle user registration.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponse: The registration page response.
    """
    # Initialize form, message, and flags
    register_form = forms.RegisterForm()
    form_valid = True
    successful_register = False
    message = ''
    response = HttpResponse()

    # Get user information from token
    logs = get_logs(request)
    token = retrieve_token(request.COOKIES)
    if not is_valid_token(token):
        redirect_invalid_user(request)
    user = retrieve_user_from_token(token)

    # Process registration form submission
    if request.method == "POST":
        register_form = forms.RegisterForm(request.POST)
        if register_form.is_valid():
            # Validate password
            if register_form.cleaned_data['password'] != register_form.cleaned_data['confirm_password']:
                message = 'Passwords do not match.'
                form_valid = False
            if not is_valid_password(register_form.cleaned_data['password']):
                message = 'The password must contain at least 8 characters, one uppercase letter, and one digit.'
                form_valid = False
            if not is_valid_email(register_form.cleaned_data['email']):
                message = 'Invalid email.'
                form_valid = False
            if form_valid:
                try:
                    # Create new user and user profile
                    user = User.objects.create_user(
                        username=register_form.cleaned_data['username'],
                        password=register_form.cleaned_data['password'],
                        email=register_form.cleaned_data['email'],
                    )
                    user_profile = models.UserProfile.objects.create(
                        user=user,
                        bio='',
                    )
                    message = f'Hello, {user.username}! You are now registered.'
                    # Generate new JWT token for user
                    refresh = RefreshToken.for_user(user)
                    access_token = str(refresh.access_token)
                    response.set_cookie(key='jwt_token', value=access_token, httponly=True, secure=True)
                    logs.username = user.username
                    if register_form.cleaned_data['authorize']:
                        logs.log = True
                    successful_register = True
                except IntegrityError:
                    message = "This username already exists. Please choose another username."
                    form_valid = False
    # Encode and set logs cookie
    logs = base64.b64encode(pickle.dumps(logs))
    logs = logs.decode('utf-8')
    response.set_cookie(key='logs', value=logs, httponly=True)

    # Render registration template with form, message, and authentication status
    template_content = render(request, 'blog_DIY/register.html', {'register_form': register_form, 'message': message, 'is_authenticated': is_authenticated(request)})
    response.content = template_content.content
    # If registration was successful, redirect to home page
    if successful_register:
        response.status_code = 302
        response['Location'] = '/'
    return response



def profile(request, uuid):
    """
    Render user profile page.

    Args:
        request (HttpRequest): The request object.
        uuid (str): The UUID of the user profile.

    Returns:
        HttpResponse: The rendered profile page.
    """
    # Get user profile from UUID
    user = get_object_or_404(models.UserProfile, profile_id=uuid)
    user_profile = user.user.profile
    # Render profile template with user profile, tutorials, and authentication status
    return render(
        request=request,
        template_name="blog_DIY/profile.html",
        context={
            "user_profile": user_profile,
            "tutorials": models.Tutorial.objects.filter(author_user=user_profile, published=True),
            "is_authenticated": is_authenticated(request),
            "is_admin": verif_admin(request)
        }
    )



@log_user_activity("my_profile")
def my_profile(request):
    """
    Render and handle user's own profile page.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponse: The rendered profile page.
    """
    # Retrieve user's token
    token = retrieve_token(request.COOKIES)
    if not is_valid_token(token):
        redirect_invalid_user(request)

    # Retrieve user and user profile
    user = retrieve_user_from_token(token)
    user_profile = models.UserProfile.objects.get(user=user)

    message_error = ''
    message_valid = ''

    if request.method == "POST":
        # Process profile form submission
        profile_form = forms.UserProfileForm(request.POST, request.FILES, instance=user_profile)
        if profile_form.is_valid():
            # Check if email format is valid
            if not(is_valid_email(profile_form.cleaned_data["new_email"])):
                profile_form.save()
                message_error = "Invalid email format"
            else:
                profile_form.save()
                message_valid = "Changes saved successfully !"
        else:
            message_error = profile_form.errors
    else:
        # Display profile form
        profile_form = forms.UserProfileForm(instance=user_profile, initial={ "new_email": user.email })

    # Render profile template with form, messages, and authentication status
    return render(
        request=request,
        template_name="blog_DIY/my_profile.html",
        context={
            "profile_form": profile_form,
            "user_profile": user_profile,
            "message_error": message_error,
            "message_valid": message_valid,
            "is_authenticated": is_authenticated(request),
            "is_admin": verif_admin(request)
        }
    )



@log_user_activity("change_password")
def change_password(request):
    """
    Handle password change request.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponse: The change password page response.
    """
    message = ''

    # Retrieve user token
    token = retrieve_token(request.COOKIES)
    if not is_valid_token(token):
        redirect_invalid_user(request)

    # Decode token to get user information
    decoded_token = jwt_decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    user = User.objects.get(id=decoded_token['user_id'])

    if request.method == 'POST':
        # Process password change form submission
        password_form = forms.ChangePasswordForm(request.POST)
        if password_form.is_valid():
            # Authenticate user with old password
            user = authenticate(
                username=user.username,
                password=password_form.cleaned_data['old_password'],
            )
            if user is None:
                message = 'Incorrect password.'
                return render(request, 'blog_DIY/change_password.html', {'password_form': password_form, 'message': message, 'is_authenticated': is_authenticated(request), 'is_admin': verif_admin(request),})
            # Validate new password
            if not is_valid_password(password_form.cleaned_data['new_password']):
                message = 'The password must contain at least 8 characters, one uppercase letter, and one digit.'
                return render(request, 'blog_DIY/change_password.html', {'password_form': password_form, 'message': message, 'is_authenticated': is_authenticated(request), 'is_admin': verif_admin(request),})
            # Check password confirmation
            if password_form.cleaned_data['new_password'] != password_form.cleaned_data['confirm_new_password']:
                message = 'Passwords do not match.'
                return render(request, 'blog_DIY/change_password.html', {'password_form': password_form, 'message': message, 'is_authenticated': is_authenticated(request), 'is_admin': verif_admin(request),})
            # Update user's password
            user.set_password(password_form.cleaned_data['new_password'])
            user.save()
            response = HttpResponse()
            response.delete_cookie('jwt_token')
            return custom_redirect(request, response, '/login', f'{user.username}\'s password has been changed successfully!')
    else:
        password_form = forms.ChangePasswordForm()

    # Render password change template with form, message, and authentication status
    return render(request, 'blog_DIY/change_password.html', {'password_form': password_form, 'message': message, 'is_authenticated': is_authenticated(request), 'is_admin': verif_admin(request),})



def reset_password(request):
    """
    Handle password reset request.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponse: The reset password page response.
    """
    message = ''
    mail = ''
    link = ''
    if request.method == 'POST':
        # Process password reset form submission
        form = forms.ResetPasswordForm(request.POST)
        if form.is_valid():
            try:
                # Get user information
                user = User.objects.get(username=form.cleaned_data['username'])
                email = user.email
                username = user.username
                message = f'We have just sent an email to {email}.'
                host = request.get_host()
                # Generate reset password link
                link = f'http://{host}/reset_password/' + str(hashlib.md5(username.encode()).hexdigest())
                mail = 'Please find below the link to reset your password.'
                # Prevent resetting admin password
                if username == 'admin':
                    message = 'You cannot reset the admin password.'
                    mail = ""
            except User.DoesNotExist:
                message = 'This user does not exist.'
            return render(request, 'blog_DIY/reset_password.html', {'form': form, 'message': message, 'mail': mail, 'link': link,'is_autenticated': is_authenticated(request), 'is_admin': verif_admin(request),})
    else:
        form = forms.ResetPasswordForm()
    # Render password reset template with form and authentication status
    return render(request, 'blog_DIY/reset_password.html', {'form': form, 'is_autenticated': is_authenticated(request), 'is_admin': verif_admin(request),})



def get_user_from_hash(hash):
    """
    Get user based on a hashed username.

    Args:
        hash (str): The hashed username.

    Returns:
        User: The user object if found, None otherwise.
    """
    # Iterate over all usernames to find a match with the provided hash
    for username in User.objects.values_list("username", flat=True):
        hashed_username = hashlib.md5(username.encode()).hexdigest()
        # Check if the hashed username matches the provided hash
        if hashed_username == hash:
            try:
                # Retrieve the user object
                user = User.objects.get(username=username)
                # Check if the user is the admin, and return None to prevent resetting the admin password
                if user.username == "admin":
                    return None
                return user
            except User.DoesNotExist:
                return None
    return None



def reset_password_hash(request, hash):
    """
    Handle password reset using hash.

    Args:
        request (HttpRequest): The request object.
        hash (str): The hashed username.

    Returns:
        HttpResponse: The reset password hash page response.
    """
    if request.method == 'POST':
        # Process password reset form submission
        password_form = forms.ResetOldPasswordForm(request.POST)
        if password_form.is_valid():
            user = get_user_from_hash(hash)
            # Validate new password
            if not is_valid_password(password_form.cleaned_data['new_password']):
                message = 'The password must contain at least 8 characters, one uppercase letter, and one digit.'
                return render(request, 'blog_DIY/reset_password_hash.html', {'password_form': password_form, 'message': message})
            # Check password confirmation
            if password_form.cleaned_data['new_password'] != password_form.cleaned_data['confirm_new_password']:
                message = 'Passwords do not match.'
                return render(request, 'blog_DIY/reset_password_hash.html', {'password_form': password_form, 'message': message})
            # Update user's password
            user.set_password(password_form.cleaned_data['new_password'])
            user.save()
            message = 'Password changed successfully.'
            return render(request, 'blog_DIY/reset_password_hash.html', {'message': message, 'is_authenticated': is_authenticated(request), 'is_admin': verif_admin(request),})
    else:
        password_form = forms.ResetOldPasswordForm()
        message = ''
        user = get_user_from_hash(hash)
        if user is not None:
            print(user.username)
            return render(request, 'blog_DIY/reset_password_hash.html', {'password_form': password_form, 'message': message, 'is_authenticated': is_authenticated(request), 'is_admin': verif_admin(request),})
        else:
            message = 'Invalid link'
            return render(request, 'blog_DIY/reset_password_hash.html', {'message': message, 'is_authenticated': is_authenticated(request), 'is_admin': verif_admin(request),})



@log_user_activity("delete_user")
def delete_user(request):
    """
    Handle user deletion request.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponse: The delete user page response.
    """
    token = retrieve_token(request.COOKIES)
    if not is_valid_token(token):
        redirect_invalid_user(request)
    user = retrieve_user_from_token(token)
    user_profile = models.UserProfile.objects.get(user=user)

    if request.method == "POST":
        try:
            # Delete user and user profile
            username = user.username
            user_profile.delete()
            user.delete()
            response = HttpResponse()
            response.delete_cookie("jwt_token")
            response.delete_cookie("logs")
            return custom_redirect(
                request=request,
                response=response,
                location="/login",
                message=f"User {username} deleted"
            )
        except User.DoesNotExist:
            return custom_redirect(
                request=request,
                response=HttpResponse(),
                location="/login",
                message="User is not logged in"
            )
    else:
        # Render delete user template with authentication status
        return render(
            request=request,
            template_name="blog_DIY/delete_user.html",
            context={
                "is_authenticated": is_authenticated(request),
                "is_admin": verif_admin(request)
            }
        )



def admin(request):
    """
    Display admin panel if user is authenticated as admin.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponse: The admin panel page response.
    """
    # Retrieve JWT token from request cookies
    token = retrieve_token(request.COOKIES)
    # Check if token is valid
    if not is_valid_token(token):
        # Redirect to invalid user page if token is not valid
        return redirect_invalid_user(request)
    # Retrieve user from token
    user = retrieve_user_from_token(token)
    if user.username == "admin":
        # Render admin panel with user profiles, tutorials, comments, and authentication status
        return render(
            request=request,
            template_name="blog_DIY/admin.html",
            context={
                "user_profiles": models.UserProfile.objects.all(),
                "tutorials": models.Tutorial.objects.all(),
                "comments": models.Comment.objects.all(),
                "is_authenticated": is_authenticated(request),
                "is_admin": verif_admin(request),
            }
        )
    else:
        # Redirect to login page with message if user is not admin
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/login",
            message="User is not admin"
        )




def admin_delete_user(request, id):
    """
    Delete a user profile by ID if the requesting user is an admin.

    Args:
        request (HttpRequest): The request object.
        id (int): The ID of the user profile to delete.

    Returns:
        HttpResponse: The redirect response.
    """
    # Retrieve JWT token from request cookies
    token = retrieve_token(request.COOKIES)
    # Check if token is valid
    if not is_valid_token(token):
        # Redirect to invalid user page if token is not valid
        return redirect_invalid_user(request)
    # Retrieve user from token
    user = retrieve_user_from_token(token)
    if user.username == "admin":
        # Retrieve user profile by ID
        user_profile = get_object_or_404(models.UserProfile, id=id)
        # Delete user profile
        user_profile.delete()
        # Redirect to admin page with success message
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/admin",
            message=f"User {user_profile.user.username} successfully deleted"
        )
    else:
        # Redirect to login page with message if user is not admin
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/login",
            message="User is not admin"
        )


def admin_delete_tutorial(request, id):
    """
    Delete a tutorial by ID if the requesting user is an admin.

    Args:
        request (HttpRequest): The request object.
        id (int): The ID of the tutorial to delete.

    Returns:
        HttpResponse: The redirect response.
    """
    # Retrieve JWT token from request cookies
    token = retrieve_token(request.COOKIES)
    # Check if token is valid
    if not is_valid_token(token):
        # Redirect to invalid user page if token is not valid
        return redirect_invalid_user(request)
    # Retrieve user from token
    user = retrieve_user_from_token(token)
    if user.username == "admin":
        # Retrieve tutorial by ID
        tutorial = get_object_or_404(models.Tutorial, id=id)
        # Delete tutorial
        tutorial.delete()
        # Redirect to admin page with success message
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/admin",
            message=f"Tutorial {tutorial.title} successfully deleted"
        )
    else:
        # Redirect to login page with message if user is not admin
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/login",
            message="User is not admin"
        )



def admin_delete_comment(request, id):
    """
    Delete a comment by ID if the requesting user is an admin.

    Args:
        request (HttpRequest): The request object.
        id (int): The ID of the comment to delete.

    Returns:
        HttpResponse: The redirect response.
    """
    # Retrieve JWT token from request cookies
    token = retrieve_token(request.COOKIES)
    # Check if token is valid
    if not is_valid_token(token):
        # Redirect to invalid user page if token is not valid
        return redirect_invalid_user(request)
    # Retrieve user from token
    user = retrieve_user_from_token(token)
    if user.username == "admin":
        # Retrieve comment by ID
        comment = get_object_or_404(models.Comment, id=id)
        comment.delete()
        # Redirect to admin page with success message
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/admin",
            message="Comment successfully deleted"
        )
    else:
        # Redirect to login page with message if user is not admin
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/login",
            message="User is not admin"
        )



# Decorator function to log user activity for admin users
@log_user_activity("admin")
def add_tutorial(request):
    # Retrieve token from request cookies
    token = retrieve_token(request.COOKIES)
    # Check if token is valid
    if not is_valid_token(token):
        # Redirect invalid user
        redirect_invalid_user(request)
    
    # Retrieve user profile from token
    user = retrieve_user_from_token(token)
    user_profile = get_object_or_404(models.UserProfile, id=user.id)

    # Check if request method is POST
    if request.method == "POST":
        # Check if 'num_formsets' is in request POST data
        if "num_formsets" in request.POST:
            # Retrieve 'num_formsets' value from request POST data
            num_formsets = int(request.POST["num_formsets"])
            # Create formset with extra forms based on 'num_formsets'
            add_content_form_set = formset_factory(forms.AddContentForm, extra=num_formsets)
            return render(
                request=request,
                template_name="blog_DIY/add_tutorial.html",
                context={
                    "tutorial_form": forms.TutorialForm(),
                    "formset": add_content_form_set(),
                    "num_formsets": num_formsets,
                    "is_authenticated": is_authenticated(request),
                    "is_admin": verif_admin(request)
                }
            )

        # Process tutorial form and content formset
        tutorial_form = forms.TutorialForm(request.POST)
        num_add_content_forms = int(request.POST.get('form-TOTAL_FORMS', 0))
        add_content_form_set = formset_factory(forms.AddContentForm, extra=num_add_content_forms)
        formset = add_content_form_set(request.POST, request.FILES)

        # Check if both tutorial form and content formset are valid
        if tutorial_form.is_valid() and formset.is_valid():
            # Save tutorial form data
            tutorial = tutorial_form.save(commit=False)
            tutorial.author_user = user_profile

            # Check if 'publish' button was clicked
            if 'publish' in request.POST:
                tutorial.published = True
            tutorial.save()

            # Save content formset data
            for form in formset:
                bodyline = form.cleaned_data.get('bodyline')
                picture = form.cleaned_data.get('picture')
                content_text = models.TextContent(tutorial_related=tutorial, bodyline=bodyline)
                content_text.save()
                content_picture = models.PictureContent(tutorial_related=tutorial, picture=picture)
                content_picture.save()

            # Redirect to user's tutorials page with success message
            return custom_redirect(
                request=request,
                response=HttpResponse(),
                location="/my_tutorials",
                message=f"Tutorial {tutorial.title} created"
            )
    else:
        # If request method is not POST, create formset with one extra form
        add_content_form_set = formset_factory(forms.AddContentForm, extra=1)
    
    # Render the tutorial form and formset in the template
    return render(
        request=request,
        template_name="blog_DIY/add_tutorial.html",
        context={
            "tutorial_form": forms.AddContentForm(),
            "formset": add_content_form_set(),
            "is_authenticated": is_authenticated(request),
            "is_admin": verif_admin(request)
        }
    )



# This function is a decorator that logs user activity when they delete a tutorial
@log_user_activity("delete_tutorial")
def delete_tutorial(request, id):
    # Retrieve the authentication token from the request cookies
    token = retrieve_token(request.COOKIES)
    # Check if the token is valid
    if not is_valid_token(token):
        # Redirect the user if the token is not valid
        redirect_invalid_user(request)
    # Retrieve the user associated with the token
    user = retrieve_user_from_token(token)
    # Retrieve the user's profile
    user_profile = get_object_or_404(models.UserProfile, id=user.id)

    # Retrieve the tutorial to be deleted
    tutorial = get_object_or_404(models.Tutorial, id=id)
    title = tutorial.title

    # Check if the user deleting the tutorial is the author of the tutorial
    if tutorial.author_user.user.username != user_profile.user.username:
        # Redirect the user if they are not the author of the tutorial
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/login",
            message="Not the right user"
        )
    else:
        # Delete the tutorial if the user is the author
        tutorial.delete()
        # Redirect the user to their tutorials page with a success message
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/my_tutorials",
            message=f"Tutorial {title} deleted"
        )



# This function is a decorator that logs user activity when they edit a tutorial
@log_user_activity("edit_tutorial")
def edit_tutorial(request, id):
    # Retrieve the authentication token from the request cookies
    token = retrieve_token(request.COOKIES)
    # Check if the token is valid
    if not is_valid_token(token):
        # Redirect the user if the token is not valid
        redirect_invalid_user(request)
    # Retrieve the user associated with the token
    user = retrieve_user_from_token(token)
    # Retrieve the user's profile
    user_profile = get_object_or_404(models.UserProfile, id=user.id)
    # Retrieve the tutorial to be edited
    tutorial = get_object_or_404(models.Tutorial, id=id)

    # Check if the user editing the tutorial is the author of the tutorial
    if tutorial.author_user.user.username != user_profile.user.username:
        # Redirect the user if they are not the author of the tutorial
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/login",
            message="Not the right user"
        )

    if request.method == "POST":
        # Process the tutorial edit form and the formset for content additions/edits
        tutorial_form = forms.TutorialForm(request.POST, instance=tutorial)
        AddContentFormSet = formset_factory(forms.AddContentForm, extra=0)
        formset = AddContentFormSet(request.POST, request.FILES, prefix='content')

        if tutorial_form.is_valid() and formset.is_valid():
            # Save the edited tutorial information
            tutorial = tutorial_form.save(commit=False)
            tutorial.author_user = user_profile

            if 'publish' in request.POST:
                tutorial.published = True
            tutorial.save()

            # Delete existing content related to the tutorial
            tutorial.text_content.all().delete()
            tutorial.picture_content.all().delete()

            # Save new content provided in the formset
            for form in formset:
                print(form.cleaned_data.get('bodyline'))
                bodyline = form.cleaned_data.get('bodyline')
                picture = form.cleaned_data.get('picture')
                content_text = models.TextContent(tutorial_related=tutorial, bodyline=bodyline)
                content_text.save()
                content_picture = models.PictureContent(tutorial_related=tutorial, picture=picture)
                content_picture.save()
            return custom_redirect(
                request=request,
                response=HttpResponse(),
                location="/my_tutorials",
                message=f"{tutorial.title} edited"
            )

    else:
        # Populate the initial data for the formset with existing tutorial content
        initial_data = []
        for i in range(0, len(tutorial.content_sorted), 2):
            initial_data.append({
                'bodyline': tutorial.content_sorted[i].bodyline,
                'picture': tutorial.content_sorted[i+1].picture,
            })
        AddContentFormSet = formset_factory(forms.AddContentForm, extra=0)
    
    # Render the tutorial edit form and the formset for content additions/edits
    return render(
        request=request,
        template_name="blog_DIY/edit_tutorial.html",
        context={
            "tutorial_form": forms.TutorialForm(instance=tutorial),
            "formset": AddContentFormSet(initial=initial_data, prefix='content'),
            "tutorial": tutorial,
            "is_authenticated": is_authenticated(request),
            "is_admin": verif_admin(request)
        }
    )



# This function is a decorator that logs user activity when they view their tutorials
@log_user_activity("my_tutorials")
def my_tutorials(request):
    # Retrieve the authentication token from the request cookies
    token = retrieve_token(request.COOKIES)
    # Check if the token is valid
    if not is_valid_token(token):
        # Redirect the user if the token is not valid
        redirect_invalid_user(request)
    # Retrieve the user associated with the token
    user = retrieve_user_from_token(token)
    # Retrieve the user's profile
    user_profile = get_object_or_404(models.UserProfile, id=user.id)
    
    # Render the user's tutorials page
    return render(
        request=request,
        template_name="blog_DIY/my_tutorials.html",
        context={
            "tutorials": models.Tutorial.objects.filter(author_user=user_profile),
            "is_authenticated": is_authenticated(request),
            "is_admin": verif_admin(request)
        }
    )



# This function is a decorator that logs user activity when they export a tutorial to XML
@log_user_activity("export_tutorial_to_xml")
def export_tutorial_to_xml(request, id):
    # Retrieve the authentication token from the request cookies
    token = retrieve_token(request.COOKIES)
    # Check if the token is valid
    if not is_valid_token(token):
        # Redirect the user if the token is not valid
        redirect_invalid_user(request)
    # Retrieve the user associated with the token
    user = retrieve_user_from_token(token)
    # Retrieve the user's profile
    user_profile = get_object_or_404(models.UserProfile, id=user.id)
    # Retrieve the tutorial to be exported
    tutorial = get_object_or_404(models.Tutorial, id=id)

    # Check if the user exporting the tutorial is the author of the tutorial
    if tutorial.author_user.user.username != user_profile.user.username:
        # Redirect the user if they are not the author of the tutorial
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/login",
            message="Not the right user"
        )

    # Create the XML structure for the tutorial
    root = etree.Element("tutorial")
    etree.SubElement(root, "title").text = tutorial.title
    etree.SubElement(root, "creation_date").text = str(tutorial.creation_date)
    etree.SubElement(root, "published").text = str(tutorial.published)

    # Add content (text or picture) to the XML structure
    content_sorted = tutorial.content_sorted
    for content_item in content_sorted:
        content_type = content_item.get_model_name()

        if content_type == 'textcontent':
            content_element = etree.SubElement(root, "text_content")
            etree.SubElement(content_element, "bodyline").text = content_item.bodyline
            etree.SubElement(content_element, "creation_date").text = str(content_item.creation_date)
        elif content_type == 'picturecontent':
            content_element = etree.SubElement(root, "picture_content")
            etree.SubElement(content_element, "picture").text = str(content_item.picture)
            etree.SubElement(content_element, "creation_date").text = str(content_item.creation_date)

    # Create the XML tree and prepare the response
    tree = etree.ElementTree(root)
    response = HttpResponse(content_type='application/xml')
    response['Content-Disposition'] = f'attachment; filename="{tutorial.title}.xml"'
    # Write the XML to the response object
    tree.write(response, encoding='utf-8', pretty_print=True, xml_declaration=True)
    return response



def import_tutorial_from_xml(request):
    # Retrieve the authentication token from the request cookies
    token = retrieve_token(request.COOKIES)
    # Check if the token is valid
    if not is_valid_token(token):
        # Redirect the user if the token is not valid
        redirect_invalid_user(request)
    # Retrieve the user associated with the token
    user = retrieve_user_from_token(token)
    # Retrieve the user's profile
    user_profile = get_object_or_404(models.UserProfile, id=user.id)

    if request.method == "POST":
        print(os.listdir())
        # Check if a file was provided in the request
        if "file" not in request.FILES:
            return HttpResponse("No file provided", status=400)

        # Get the XML file from the request
        xml_file = request.FILES["file"]
        # Parse the XML file
        tree = etree.parse(xml_file, etree.XMLParser(resolve_entities=True))
        root = tree.getroot()

        # Extract tutorial information from the XML
        title = root.find("title").text
        creation_date = root.find("creation_date").text
        published = root.find("published").text

        # Create a new tutorial object
        tutorial = models.Tutorial.objects.create(title=title, creation_date=creation_date, published=published, author_user=user_profile)

        # Extract and create text content from the XML
        for content_element in root.findall('text_content'):
            bodyline = content_element.find('bodyline').text
            creation_date = content_element.find('creation_date').text
            models.TextContent.objects.create(tutorial_related=tutorial, bodyline=bodyline, creation_date=creation_date)

        # Extract and create picture content from the XML
        for content_element in root.findall('picture_content'):
            picture = content_element.find('picture').text
            creation_date = content_element.find('creation_date').text
            models.PictureContent.objects.create(tutorial_related=tutorial, picture=picture, creation_date=creation_date)

        # Redirect the user to their tutorials page with a success message
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/my_tutorials",
            message=f"Tutorial {tutorial.title} successfully imported"
        )
    else:
        # Render the import tutorial page if the request method is not POST
        return render(
            request=request,
            template_name="blog_DIY/import_tutorial.html",
            context={
                "is_authenticated": is_authenticated(request),
                "is_admin": verif_admin(request)
            }
        )



def tutorial(request, id):
    # Retrieve the authentication token from the request cookies
    token = retrieve_token(request.COOKIES)
    # Check if the token is valid
    if not is_valid_token(token):
        # Redirect the user if the token is not valid
        redirect_invalid_user(request)
    # Retrieve the user associated with the token
    user = retrieve_user_from_token(token)
    # If user exists, retrieve the user's profile
    if user:
        user_profile = get_object_or_404(models.UserProfile, id=user.id)
    # Retrieve the tutorial to be displayed
    tutorial = get_object_or_404(models.Tutorial, id=id)
    # Retrieve all comments related to the tutorial
    comments = tutorial.comment.all()

    if request.method == "POST" and is_authenticated:
        # Process the comment form if the request method is POST and the user is authenticated
        comment_form = forms.CommentForm(request.POST)
        if comment_form.is_valid():
            new_comment = comment_form.save(commit=False)
            new_comment.author_user = user_profile
            new_comment.tutorial_related = tutorial
            new_comment.save()
            return custom_redirect(
                request=request,
                response=HttpResponse(),
                location=f"/tutorial/{id}",
                message="Comment saved"
            )
    # Render the tutorial page with the tutorial, comments, and comment form
    return render(
        request=request,
        template_name="blog_DIY/tutorial.html",
        context={
            "tutorial": tutorial,
            "comments": tutorial.comment.all(),
            "comment_form": forms.CommentForm(),
            "is_authenticated": is_authenticated(request),
            "is_admin": verif_admin(request)
        }
    )



def search_tutorial(request):
    message = ''
    tutorials = []
    query = request.GET.get("q")
    if query:
        try:
            # Use raw SQL to perform a search query
            with connection.cursor() as cursor:
                cursor.execute(f"""
                    SELECT blog_DIY_tutorial.id, blog_DIY_tutorial.title, blog_DIY_tutorial.creation_date, 
                        auth_user.username as author_username,
                        blog_DIY_tutorial.published
                    FROM blog_DIY_tutorial
                    INNER JOIN blog_DIY_userprofile ON blog_DIY_tutorial.author_user_id = blog_DIY_userprofile.id
                    INNER JOIN auth_user ON blog_DIY_userprofile.user_id = auth_user.id
                    WHERE (blog_DIY_tutorial.title LIKE '%{query}%' OR auth_user.username LIKE '%{query}%') AND blog_DIY_tutorial.published = True
                """)
                # Fetch all results as dictionaries
                dict_tutorials = dictfetchall(cursor)
                tutorials = []
                # Retrieve Tutorial objects based on the IDs from the SQL query
                for tutorial in dict_tutorials:
                    tutorials.append(models.Tutorial.objects.get(id=tutorial['id']))
        except:
            message = 'There is an error in the SQL request.'
    else:
        # If no query is provided, return all published tutorials
        tutorials = models.Tutorial.objects.filter(published=True)
    # Render the search results page
    return render(
        request=request,
        template_name="blog_DIY/search_tutorial.html",
        context={
            "tutorials": tutorials,
            "query": query,
            "message": message,
            "is_authenticated": is_authenticated(request),
            "is_admin": verif_admin(request)
        }
    )



def dictfetchall(cursor):
    # Get the column names from the cursor description
    columns = [col[0] for col in cursor.description]
    # Create a list of dictionaries where each dictionary represents a row
    return [dict(zip(columns, row)) for row in cursor.fetchall()]



def delete_comment(request, id):
    # Retrieve the comment to be deleted
    comment = get_object_or_404(models.Comment, id=id)
    # Delete the comment
    comment.delete()
    # Redirect the user to the tutorial page from which the comment was deleted
    return custom_redirect(
        request=request,
        response=HttpResponse(),
        location=f"/tutorial/{comment.tutorial_related.id}",
        message="Comment deleted"
    )

