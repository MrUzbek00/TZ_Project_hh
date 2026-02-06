from . import views
from django.urls import path

urlpatterns = [
    path('', views.login, name='login'),
    path("logout/", views.logout, name="logout"),
    path('signup/', views.signup, name='signup'),
    path('home/', views.home, name='home'),
    path('update_user/<int:user_id>/', views.update_user, name='update_user'),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
]
