from django.shortcuts import render
from .models import UserProfile, Session, Roles
from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from datetime import timedelta
from django.http import HttpResponse
from .permissions import can

SESSION_COOKIE_NAME = "custom_sessionid"
SESSION_TTL_HOURS = 24


def require_login(request):
    """
    Вспомогательная функция для проверки аутентификации пользователя.

    Использует кастомную систему авторизации:
      - CustomAuthMiddleware устанавливает request.custom_user
      - Если пользователь не найден или неактивен — возвращает 401

    Возвращает:
      - HttpResponse(401), если пользователь не аутентифицирован
      - None, если пользователь аутентифицирован и активен
    """
    user = getattr(request, "custom_user", None)
    if not user or not user.is_active:
        return HttpResponse("Unauthorized", status=401)
    return None


def login(request):
    """
    Аутентификация пользователя по email и паролю.

    Логика:
      - POST:
          * поиск пользователя по email
          * проверка хэшированного пароля
          * проверка is_active
          * создание кастомной сессии (Session)
          * установка cookie с UUID сессии
          * редирект на home
      - GET:
          * отображение страницы логина

    Используется собственная таблица Session, а не Django auth.
    """
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Поиск пользователя и проверка пароля
        user = UserProfile.objects.filter(email=email).first()
        if not user or not user.is_active or not check_password(password, user.password):
            messages.error(request, 'Invalid email or password')
            return render(request, 'Tz_App/login.html')

        # Создание кастомной сессии
        session = Session.objects.create(
            user=user,
            expires_at=timezone.now() + timedelta(hours=SESSION_TTL_HOURS),
            is_active=True
        )
       

        # Установка cookie с UUID сессии
        resp = redirect("home")
        resp.set_cookie(
            SESSION_COOKIE_NAME,
            str(session.id),
            httponly=True,
            samesite="Lax",
        )
        return resp

    return render(request, 'Tz_App/login.html')


def logout(request):
    """
    Выход пользователя из системы.

    Логика:
      - получение UUID сессии из cookie
      - деактивация сессии в БД
      - удаление cookie
      - редирект на страницу логина
    """
    session_id = request.COOKIES.get(SESSION_COOKIE_NAME)
    if session_id:
        Session.objects.filter(id=session_id).update(is_active=False)

    resp = redirect("login")
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


def signup(request):
    """
    Регистрация нового пользователя.

    Логика:
      - POST:
          * проверка совпадения паролей
          * проверка уникальности email
          * назначение роли 'user' по умолчанию
          * хэширование пароля
          * создание UserProfile
          * редирект на login
      - GET:
          * отображение формы регистрации
    """
    if request.method == 'POST':
        name = request.POST.get('name')
        surname = request.POST.get('surname')
        peternity = request.POST.get('peternity')
        email = request.POST.get('email')
        password_1 = request.POST.get('password_1')
        password_2 = request.POST.get('password_2')

        # Проверка совпадения паролей
        if password_1 != password_2:
            messages.error(request, 'Пароли не совпадают')
            return render(request, 'Tz_App/signup.html')

        # Проверка уникальности email
        if UserProfile.objects.filter(email=email).exists():
            messages.error(request, 'Email уже зарегистрирован')
            return render(request, 'Tz_App/signup.html')

        # Назначение роли "user" по умолчанию
        default_role = Roles.objects.get(role="user")

        user = UserProfile(
            name=name,
            last_name=surname,
            paternity_name=peternity,
            email=email,
            password=make_password(password_1),
            role=default_role
        )
        user.save()
        messages.success(request, 'Аккаунт успешно создан')
        return redirect('login')

    return render(request, 'Tz_App/signup.html')


def home(request):
    """
    Главная страница со списком пользователей.

    Доступ определяется через RBAC (can()):
      - Если есть read_all_permission -> показываем список пользователей (возможно с фильтрацией)
      - Иначе, если есть read_permission и пользователь владелец -> показываем только свой профиль
      - Иначе -> 403

    Важно:
      - Нельзя сразу возвращать 403, если нет read_all_permission, потому что у роли может быть
        read_permission (чтение только своего профиля).
    """
    unauth = require_login(request)
    if unauth:
        return unauth

    cu = request.custom_user
    # 1) Сначала проверяем "чтение всех"
    result_all = can(cu, "users", "read")

    if result_all.allowed and result_all.reason == "read_all_allowed":
        # Если вы НЕ хотите, чтобы manager видел admin — включите фильтрацию здесь.
        # Если хотите, чтобы manager видел всех — оставьте UserProfile.objects.all()
        if cu.role and cu.role.role == "manager":
            users = UserProfile.objects.exclude(role__role="admin")
        else:
            users = UserProfile.objects.all()

        context = {
            "users": users,
            "cu": cu,
        }

        # Только админу передаём список ролей (для select в шаблоне)
        if cu.role and cu.role.role == "admin":
            context["roles"] = Roles.objects.all()

        return render(request, "Tz_App/home.html", context)

    # 2) Если "чтение всех" не разрешено — проверяем "чтение своего профиля"
    result_own = can(cu, "users", "read", owner_id=cu.user_id)
    if result_own.allowed:
        user = UserProfile.objects.get(user_id=cu.user_id)
        return render(request, "Tz_App/home.html", {"users": [user], "cu": cu})

    # 3) Если нет ни read_all, ни read_own — запрещаем доступ
    # (возвращаем причину/статус из last check)
    return HttpResponse(result_own.reason, status=result_own.status_code)


def update_user(request, user_id):
    """
    Обновление данных пользователя с учётом RBAC и владения объектом.

    Проверки:
      - пользователь должен быть аутентифицирован
      - проверка прав через can():
          * update_all_permission → можно обновлять любого
          * update_permission + owner → можно обновлять только себя
          * иначе → 403

    Используется только POST-запрос (форма на home.html).
    """
    unauth = require_login(request)
    if unauth:
        return unauth

    cu = request.custom_user

    users = UserProfile.objects.filter(user_id=user_id).first()
    if not users:
        return HttpResponse("Not found", status=404)

    # Проверка прав доступа
    result = can(cu, "users", "update", owner_id=users.user_id)
    if not result.allowed:
        return HttpResponse(result.reason, status=result.status_code)

    if request.method == "POST":
        users.name = request.POST.get("name")
        users.last_name = request.POST.get("last_name")
        users.paternity_name = request.POST.get("paternity_name")
        users.email = request.POST.get("email")
        users.role = request.POST.get("role")

        # Пароль обновляется только если был введён новый
        pw = request.POST.get("password")
        if pw:
            users.password = make_password(pw)

        users.save()
        messages.success(request, "User updated successfully")
        return redirect("home")

    return HttpResponse("Method not allowed", status=405)


def delete_user(request, user_id):
    """
    Удаление пользователя (soft delete) с учётом RBAC.

    Логика:
      - только POST
      - проверка аутентификации
      - проверка прав через can():
          * delete_all_permission → можно удалить любого
          * delete_permission + owner → можно удалить только себя
      - soft delete (is_active=False)
      - деактивация всех сессий пользователя
    """
    if request.method != "POST":
        return HttpResponse("Method not allowed", status=405)

    unauth = require_login(request)
    if unauth:
        return unauth

    target = UserProfile.objects.filter(user_id=user_id).first()
    if not target:
        return HttpResponse("Not found", status=404)

    result = can(request.custom_user, "users", "delete", owner_id=target.user_id)
    if not result.allowed:
        return HttpResponse(result.reason, status=result.status_code)

    target.is_active = False
    target.save()
    Session.objects.filter(user=target).update(is_active=False)

    messages.success(request, "User deleted successfully")
    return redirect("home")
