import logging
from django.shortcuts import render
from django.views import generic
from django.http import HttpResponse
from django.shortcuts import redirect
from src.facebook_core.fb_business import FBBusiness
from src.facebook_core.utils import Utils

logger = Utils.get_logger('login_facebook')


def facebook_login(request):
    fb = FBBusiness(logger=logger)
    return redirect(fb.facebook_login())


def authorized(request):
    code = request.GET['code']
    fb = FBBusiness(logger=logger)
    data = fb.authorized(code=code,
                         redirect_uri='https://ff7e3ac981ca.ngrok.io/merchant/facebook/token')
    for key, value in data.items():
        request.session[key] = value

    return HttpResponse(f'Hello {request.session["username"]}')
