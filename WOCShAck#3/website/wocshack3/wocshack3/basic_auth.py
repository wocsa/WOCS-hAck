import base64
from django.contrib.auth import authenticate
from django.http import HttpResponse
from django.contrib.auth.models import User

def basic_auth_required(application):
    def wrapped_application(environ, start_response):
        # Get the Authorization header from the request
        auth_header = environ.get('HTTP_AUTHORIZATION')
        if auth_header:
            # Split the authorization header into its type and credentials
            auth_type, credentials = auth_header.split(' ', 1)
            # Check if the authorization type is 'Basic'
            if auth_type.lower() == 'basic':
                try:
                    # Decode the base64-encoded credentials and split them into username and password
                    username, password = base64.b64decode(credentials).decode('utf-8').split(':', 1)
                except ValueError:
                    pass
                else:
                    # Authenticate the user using Django's authenticate method
                    user = authenticate(username=username, password=password)
                    # Check if the user is authenticated and active
                    if user is not None and user.is_active:
                        # If authenticated, pass the request to the original application
                        return application(environ, start_response)
        # If authentication fails, return a 401 Unauthorized response
        start_response('401 Unauthorized', [('WWW-Authenticate', 'Basic realm="wocshack3"'), ('Content-Type', 'text/plain')])
        return [b'Unauthorized']

    return wrapped_application
