import json
from django.http import HttpResponse
from django.contrib.auth import views as auth_views
from django.contrib import auth as auth_helpers
from django.views.decorators import debug
from django.shortcuts import redirect

from oauth2_provider import views as oauth_views


@debug.sensitive_post_parameters()
def login(request, template_name='login/login.html'):
    """
    :param request: HTTP Request
    :param template_name: Name of the login template to use
    :return: On POST, returns a JSON object indicating the status of the login.
             On GET, renders the default Django login view.
    """
    if request.method == 'POST':
        response_data = {}

        username = request.POST['username']
        password = request.POST['password']
        user = auth_helpers.authenticate(username=username, password=password)
        if user is not None:
            auth_helpers.login(request, user)

            response_data['login'] = True
        else:
            # Return an 'invalid login' error message.
            response_data['login'] = False
            response_data['detail'] = 'Username or password is invalid.'

        return HttpResponse(json.dumps(response_data),
                            content_type="application/json")

    if request.method == 'GET':
        return auth_views.login(request, template_name=template_name)


def login_redirect(request):
    try:
        next_page = request.GET['next']
        next_page = '&next=' + next_page
    except KeyError:
        next_page = ""

    return redirect("{0}?idp=jacobs{1}".format(reverse("social:begin", kwargs={'backend': 'saml'}), next_page))


class AuthorizationView(oauth_views.AuthorizationView):
    template_name = "login/authorize.html"

from django.urls import reverse
from social_django.utils import load_backend, load_strategy


def saml_metadata(request):
    complete_url = reverse('social:complete', args=("saml", ))
    saml_backend = load_backend(
        load_strategy(request),
        "saml",
        redirect_uri=complete_url,
    )
    metadata, errors = saml_backend.generate_metadata_xml()
    if not errors:
        return HttpResponse(content=metadata, content_type='text/xml')
