from django.utils import timezone
from .models import Session

SESSION_COOKIE_NAME = "custom_sessionid"

class CustomAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.custom_user = None
        request.custom_session = None

        session_id = request.COOKIES.get(SESSION_COOKIE_NAME)
        if session_id:
            sess = (
                Session.objects.select_related("user")
                .filter(id=session_id, is_active=True, expires_at__gt=timezone.now())
                .first()
            )
            if sess and sess.user and sess.user.is_active:
                request.custom_user = sess.user
                request.custom_session = sess

        

        return self.get_response(request)