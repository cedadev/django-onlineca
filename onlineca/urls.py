# -*- coding: utf-8 -*-
"""
URL configuration for the django-onlineca package.
"""

from django.conf.urls import url

from . import views


app_name = 'onlineca'
urlpatterns = [
    url(r'^trustroots/$', views.trustroots, name="trustroots"),
    url(r'^certificate/$', views.certificate, name="certificate"),
]
