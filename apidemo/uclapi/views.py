from django.shortcuts import render, HttpResponse, redirect
from django.http import JsonResponse
from django.core.serializers.json import DjangoJSONEncoder
from django.views.decorators.csrf import csrf_protect
import requests

from .models import OAuthToken
from .helpers import generate_state

import base64
import hashlib
import hmac
import os
import json
import requests


def render_login_button(request):
    return render(request, 'login.html')


@csrf_protect
def process_login(request):
    state = generate_state()
    request.session["state"] = state
    auth_url = os.environ.get("UCLAPI_URL") + "/oauth/authorise"
    auth_url += "?client_id=" + os.environ.get("UCLAPI_CLIENT_ID")
    auth_url += "&state=" + state

    return redirect(auth_url)


def callback(request):
    try:
        result = request.GET.get("result")
    except KeyError:
        return JsonResponse({
            "error": "No result parameter passed."
        })

    if result == "allowed":
        return allowed(request)
    elif result == "denied":
        return denied(request)
    else:
        return JsonResponse({
            "ok": False,
            "error": "Result was not allowed or denied."
        })


def allowed(request):
    try:
        code = request.GET.get("code")
        client_id = request.GET.get("client_id")
        state = request.GET.get("state")
    except KeyError:
        return JsonResponse({
            "error": "Parameters missing from request."
        })

    try:
        session_state = request.session["state"]
    except KeyError:
        return JsonResponse({
            "ok": False,
            "error": "There is no session cookie set containing a state"
        })

    hmac_digest = hmac.new(bytes(os.environ.get("UCLAPI_CLIENT_SECRET"), 'ascii'),
                           msg=code.encode('ascii'),
                           digestmod=hashlib.sha256).digest()
    client_secret_proof = base64.b64encode(hmac_digest).decode()

    url = os.environ.get("UCLAPI_URL") + "/oauth/token"
    params = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_secret_proof': client_secret_proof
    }

    r = requests.get(url, params=params)

    try:
        token_data = r.json()

        if token_data["ok"] is not True:
            return JsonResponse({
                "ok": False,
                "error": "An error occurred: " + token_data["error"]
            })

        if token_data["state"] != state:
            return JsonResponse({
                "ok": False,
                "error": "The wrong state was returned"
            })

        if token_data["client_id"] != client_id:
            return JsonResponse({
                "ok": False,
                "error": "The wrong client ID was returned"
            })

        token_code = token_data["token"]
        scope_data = json.loads(token_data["scope"])
    except KeyError:
        return JsonResponse({
            "ok": False,
            "error": "Proper JSON was not returned by the token endpoint"
        })

    token = OAuthToken(code=token_code)
    try:
        token.private_roombookings = scope_data["private_roombookings"]
    except KeyError:
        pass

    try:
        token.private_timetable = scope_data["private_timetable"]
    except KeyError:
        pass

    try:
        token.private_uclu = scope_data["private_uclu"]
    except KeyError:
        pass

    token.save()

    url = os.environ.get("UCLAPI_URL") + "/oauth/user/data"
    params = {
        'token': token_code,
        'client_secret_proof': client_secret_proof
    }

    r = requests.get(url, params=params)

    return JsonResponse(r.json())


def denied(request):
    return render(request, 'denied.html', {
                  "state": request.GET.get("state", None)})
