from functools import wraps
from pickle import loads as pickle_loads
from base64 import b64decode


class Logs:
    def __init__(self, username, log):
        self.username = username
        self.log = log


def log_user_activity(view_name):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            logs = get_logs(request)
            if logs.log:
                print(f"{logs.username} is in {view_name} view")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def get_logs(request):
    if "logs" in request.COOKIES:
        logs = request.COOKIES["logs"]
        return pickle_loads(b64decode(logs))
    return Logs("None", False)
