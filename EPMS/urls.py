"""
URL configuration for E-commerce Product Management System project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""


from django.contrib import admin
from django.urls import path
from EPMS import views
from rest_framework.urlpatterns import format_suffix_patterns
from django.urls import re_path
from django.contrib.auth import views as auth_views
from django.urls import path
from django.shortcuts import redirect

app_name="interview"
urlpatterns = [
    path('admin/', admin.site.urls),
    path('',views.home, name='home'),
    path('products/', views.product_list),
    path('products/<int:id>/', views.product_detail),
    path('categories/', views.category_list),
    path('categories/<int:id>/', views.category_detail),
    path('user/products/',views.user_products_view, name='user_products'),
    path('products/<int:product_id>/reviews/',views.review_list, name='review_list'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('signup/', views.signup, name='register'),
    path('login_redirect/', views.login_redirect, name='login_redirect'),
]


urlpatterns = format_suffix_patterns(urlpatterns)