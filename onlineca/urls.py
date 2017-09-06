"""
URL configuration for the django-onlineca package.
"""

from django.conf import settings
from django.conf.urls import url, include

from . import views


app_name = 'onlineca'
urlpatterns = [
    url(r'^trustroots/$', views.trustroots, name="trustroots"),
    url(r'^certificate/$', views.certificate, name="certificate"),
]
