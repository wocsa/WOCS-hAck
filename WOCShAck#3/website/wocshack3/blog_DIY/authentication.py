from django.conf import settings
from django.http import HttpResponse
from jwt import encode as jwt_encode, decode as jwt_decode
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, DecodeError
from .logs_manager import log_user_activity
from re import match as re_match
from django.contrib.auth.models import User
from django.template import engines
from django.core.exceptions import ObjectDoesNotExist


def is_valid_token(token):
    """
    Check if a JWT token is valid.

    Args:
        token (str): The JWT token to validate.

    Returns:
        bool: True if the token is valid, False otherwise.
    """
    try:
        # Decode the token using the secret key and the HS256 algorithm
        jwt_decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        # If decoding succeeds, return True
        return True
    except ExpiredSignatureError:
        # If the token has expired, print a message and return False
        print("Token expired")
        return False
    except (InvalidTokenError, DecodeError):
        # If the token is invalid, print a message and return False
        print("Invalid token")
        return False
    except Exception as exc:
        # If an unknown error occurs, print the error message and return False
        print(f"Unknown error: {exc}")
        return False



def is_authenticated(request):
    """
    Check if a request contains a valid JWT token for authentication.

    Args:
        request (HttpRequest): The request object containing the JWT token in cookies.

    Returns:
        bool: True if the request is authenticated, False otherwise.
    """
    # Get the JWT token from the request cookies
    token = request.COOKIES.get("jwt_token", None)
    if token:
        # Convert the token to bytes if it is a string
        if isinstance(token, str):
            token = token.encode()
        # Check if the token is valid
        return is_valid_token(token)
    # If no token is found, return False
    return False



@log_user_activity("verif_admin")
def verif_admin(request):
    """
    Verify if the user making the request is an admin.

    Args:
        request (HttpRequest): The request object.

    Returns:
        bool: True if the user is an admin, False otherwise.
    """
    # Retrieve the JWT token from the request cookies
    token = retrieve_token(request.COOKIES)
    # Check if the token is valid
    if not is_valid_token(token):
        # If the token is invalid, redirect the user to the invalid user page
        return redirect_invalid_user(request)
    # Retrieve the user object from the token
    user = retrieve_user_from_token(token)
    # Check if the user is an admin
    return user.username == "admin"



def redirect_non_admin_user(request):
    """
    Redirect non-admin users to the login page.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponseRedirect: Redirects to the login page if the user is not an admin.
    """
    if not verif_admin(request):
        # If the user is not an admin, redirect to the login page
        return custom_redirect(
            request=request,
            response=HttpResponse(),
            location="/login",
            message="User is not admin"
        )



def is_valid_email(email):
    """
    Check if an email address is valid.

    Args:
        email (str): The email address to validate.

    Returns:
        bool: True if the email is valid, False otherwise.
    """
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re_match(pattern, email) is not None



def is_valid_password(password):
    """
    Check if a password meets the criteria for validity.

    Args:
        password (str): The password to validate.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$'
    return re_match(pattern, password) is not None



def retrieve_token(cookies):
    """
    Retrieve the JWT token from cookies.

    Args:
        cookies (dict): The dictionary containing cookies.

    Returns:
        str: The JWT token if found, otherwise None.
    """
    return cookies.get("jwt_token", None)



def redirect_invalid_user(request):
    """
    Redirect users who are not logged in to the login page.

    Args:
        request (HttpRequest): The request object.

    Returns:
        HttpResponseRedirect: Redirects to the login page.
    """
    return custom_redirect(
        request=request,
        response=HttpResponse(),
        location="/login",
        message="User is not logged in"
    )



def retrieve_user_from_token(token):
    """
    Retrieve a user object from a JWT token.

    Args:
        token (str): The JWT token containing user information.

    Returns:
        User: The user object if found, otherwise None.
    """
    try:
        decoded_token = jwt_decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return User.objects.get(id=decoded_token["user_id"])
    except ExpiredSignatureError:
        # If the token has expired, print a message and return None
        print("Token expired")
        return None
    except (InvalidTokenError, DecodeError):
        # If the token is invalid, print a message and return None
        print("Invalid token")
        return None
    except ObjectDoesNotExist:
        # If the user does not exist, print a message and return None
        print("User not found")
        return None
    except Exception as e:
        # If an unknown error occurs, print the error message and return None
        print(f"An error occurred: {e}")
        return None



def custom_redirect(request, response, location, message):
    """
    Create a custom redirect response with a message.

    Args:
        request (HttpRequest): The request object.
        response (HttpResponse): The response object to modify.
        location (str): The URL to redirect to.
        message (str): The message to display in the response body.

    Returns:
        HttpResponse: The modified response object.
    """
    # Set the response status code to 302 (Redirect)
    response.status_code = 302
    # Set the Location header to the specified location
    response["Location"] = location
    # Create a simple HTML template with the message
    engine = engines["django"]
    template = engine.from_string("<html><body>" + message + "</body></html>")
    # Render the template with an empty context and set the response content
    response.content = template.render({}, request)
    return response

