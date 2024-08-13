"""
WSGI config for wocshack3 project.

It exposes the WSGI callable as a module-level variable named ``application``.
"""

import os
from django.core.wsgi import get_wsgi_application
from wocshack3.basic_auth import basic_auth_required  # Adjust the import based on where you placed the basic_auth.py file

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'wocshack3.settings')

application = get_wsgi_application()
#application = basic_auth_required(application)
