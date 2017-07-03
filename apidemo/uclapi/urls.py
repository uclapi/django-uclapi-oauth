from django.conf.urls import include, url
from . import views

urlpatterns = [
    url(r'login/process', views.process_login),
    url(r'login/button', views.render_login_button),
    url(r'callback', views.callback),
    url(r'token/test', views.token_test)
]
