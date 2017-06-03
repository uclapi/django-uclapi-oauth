from django.shortcuts import render, HttpResponse, redirect
from django.http import JsonResponse
from django.core.serializers.json import DjangoJSONEncoder
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie, csrf_protect
import requests

from .models import State, OAuthToken

import os
import json

def getState(request):
    state = State()
    state.save()
    return JsonResponse({
        "state": state.code
    })

def denied(request):
    return render(request, 'denied.html', {
        "state": request.GET.get("state", None)
    })


@csrf_exempt
def verify(request):
    try:
        client_id = request.POST.get("client_id")
        verification_data = request.POST.get("verification_data")
        state_code = request.POST.get("state")
        client_secret = os.environ.get("UCLAPI_CLIENT_SECRET")
    except:
        return JsonResponse({
            "error": "Invalid data passed"
        })
    
    if os.environ.get("UCLAPI_CLIENT_ID") != client_id:
        return JsonResponse({
            "error": "Client ID does not match"
        })

    try:
        state = State.objects.get(code=state_code)
        if (state.verified):
            return JsonResponse({
                "error": "State already verified"
            })
        
        state.verified = True
        state.save()
    except:
        return JsonResponse({
            "error": "Invalid state"
        })

    return JsonResponse({
        "client_secret": client_secret,
        "verification_data": verification_data
    })

@csrf_exempt
def token(request):
    try:
        state_code = request.POST.get("state")
        client_id = request.POST.get("client_id")
        token_code = request.POST.get("token")
        scope = json.loads(request.POST.get("scope"))

    except:
        return JsonResponse({
            "error": "Token request was malformed"
        })

    if os.environ.get("UCLAPI_CLIENT_ID") != client_id:
        return JsonResponse({
            "error": "Client ID not valid"
        })

    try:
        state = State.objects.get(code=state_code)
    except:
        return JsonResponse({
            "error": "State does not exist"
        })

    token = OAuthToken(
        code=token_code,
        private_roombookings=scope["private_roombookings"],
        private_timetable=scope["private_timetable"],
        private_uclu=scope["private_uclu"]
    )

    token.save()
    state.token = token
    state.save()

    return JsonResponse({
        "ok": "All data received"
    })

@csrf_exempt
def callback(request):
    try:
        client_id = request.GET.get("client_id")
        state_code = request.GET.get("state")

        state = State.objects.get(code=state_code)
        token = state.token
    except:
        return JsonResponse({
            "error": "Invalid data given in URL"
        })

    url = os.environ.get("UCLAPI_URL") + "/oauth/user/data"
    r = requests.get(url, params={
        "token": token.code
    })

    return JsonResponse(r.json())