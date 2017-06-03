from django.conf.urls import include, url
from . import views

urlpatterns = [
    url(r'getstate$', views.getState),
    url(r'callback/denied$', views.denied),
    url(r'callback/verify$', views.verify),
    url(r'callback/token$', views.token),
    url(r'callback', views.callback)
]