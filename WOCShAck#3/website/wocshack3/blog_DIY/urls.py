from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
# from django.contrib import admin  #  Use it for access to the Django Admin's page
from . import views


urlpatterns = [
    # User
    path('', views.home, name='home'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('register/', views.register_user, name='register'),
    path('profile/<str:uuid>', views.profile, name='profile'),
    path('my_profile/', views.my_profile, name='my_profile'),
    path('change_password/', views.change_password, name='change_password'),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('reset_password/<str:hash>', views.reset_password_hash, name='reset_password_hash'),
    path('delete_user/', views.delete_user, name='delete_user'),
    path('admin/', views.admin, name='admin'),  # Custom admin's page
    # path('admin/', admin.site.urls),  #  for access to the Django Admin's page
    path('admin/delete_user/<str:id>', views.admin_delete_user, name='admin_delete_user'),
    path('admin/delete_tutorial/<int:id>', views.admin_delete_tutorial, name='admin_delete_tutorial'),
    path('admin/delete_comment/<int:id>', views.admin_delete_comment, name='admin_delete_comment'),
    # Tutorials
    path('add_tutorial/', views.add_tutorial, name='add_tutorial'),
    path('delete_tutorial/<int:id>', views.delete_comment, name='delete_comment'),
    path('edit_tutorial/<int:id>/', views.edit_tutorial, name='edit_tutorial'),
    path('delete_tutorial/<int:id>/', views.delete_tutorial, name='delete_tutorial'),
    path('my_tutorials/', views.my_tutorials, name='my_tutorials'),
    path('export_tutorial/<int:id>/', views.export_tutorial_to_xml, name='export_tutorial'),
    path('import_tutorial/', views.import_tutorial_from_xml, name='import_tutorial'),
    path('tutorial/<str:id>', views.tutorial, name='tutorial'),
    path('search_tutorial/', views.search_tutorial, name='search_tutorial'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)