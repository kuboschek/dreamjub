from django.conf.urls import include, url
from django.shortcuts import redirect

from . import views
from oauth2_provider import views as oauth_views
from social_django import urls as saml_urls

urlpatterns = [
    url(r'^$', views.login_redirect, name='login'),
    url(r'^saml/', include(saml_urls)),
    url(r'^saml/metadata/$', views.saml_metadata),
    url(r'^o/', include([
        url(r'^authorize/$', views.AuthorizationView.as_view(),
            name="authorize"),
        url(r'^token/$', oauth_views.TokenView.as_view(), name="token"),
        url(r'^revoke_token/$', oauth_views.RevokeTokenView.as_view(),
            name="revoke-token"),
        ]))
]
