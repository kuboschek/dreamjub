import json
from django.http import HttpResponse
from django.contrib.auth import views as auth_views
from django.contrib import auth as auth_helpers
from django.views.decorators import debug
from django.shortcuts import redirect, render
from django.core import mail

from django.contrib.auth import models as auth_models

from oauth2_provider import views as oauth_views
from sesame import utils as token_utils


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

@debug.sensitive_post_parameters()
def magic_login(request, template_name='login/magic_login.html'):
    # get email, next param
    if request.method == 'POST':
        response_data = {}
        success = True

        users = auth_models.User.objects.filter(email=request.POST['email'])

        if users.count() != 1:
            success = False
        else:
            user = users.first()
            link = "https://{0}{1}{2}".format(request.META['HTTP_HOST'], request.POST['next'], token_utils.get_query_string(user))

            email_content = "Hey {0},\ndid you just try to log in?\n If yes, here's your login link:\n\n{1}\nIf no, ignore this mail.\n\n\nDO NOT REPLY TO THIS MAIL. WE DON'T READ MAIL.".format(user.first_name, link)

            response = mail.send_mail('dreamjub login link', email_content, 'noreply@jacobs.university', [user.email])

            if response != 1:
                success = False

        if success:
            response_data['success'] = True
        else:
            # Return an 'invalid login' error message.
            response_data['success'] = True
            # response_data['detail'] = 'Something wrong.'

        return HttpResponse(json.dumps(response_data), content_type="application/json")

    if request.method == 'GET':
        return render(request, template_name=template_name, context={'next': request.GET['next']})

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
