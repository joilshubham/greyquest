from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth import authenticate, login, logout
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
import json, requests, random
from .models import user_cookie_consent

@csrf_protect
def user_login(request, err_msg = None):
    if request.method == 'GET':
        return render(request, 'login.html')
    if request.method == 'POST':
        if 'sign_in' in request.POST:
            username = request.POST['user']
            password = request.POST['pass']
            user = authenticate(username=username, password=password)
            if (user is None):
                return render(request, 'login.html', {'err_msg' : 'The username and password combination is incorrect'})
            else:
                login(request, user)
                request.session.set_expiry(0)
                request.session['username']= username
                request.session['password']= password
                print(request.session.items())
                return redirect('/dashboard')
        if 'sign_up' in request.POST:
            error_msg =[]
            username = request.POST['user']
            password = request.POST['pass']
            repeat = request.POST['repeat_pass']
            email = request.POST['email']
            if password != repeat:
                error_msg.append('Please enter same password twice.')
            try:
                validate_email(email)
            except ValidationError:
                error_msg.append('Enter a valid email address.')
            if error_msg == []:
                user = User.objects.create_user(username=username,
                                         email=email,
                                         password=password)
                login(request, user)

                dashboard_data = error_msg
                return redirect('/dashboard')
            else:
                err_msg = ''
                for msg in error_msg:
                    err_msg += msg
                return render(request, 'login.html', {'err_msg': err_msg})


@csrf_protect
@login_required()
def dashboard(request):
    user = request.user.username
    user_id = User.objects.get(username=user).id
    try :
        consent = user_cookie_consent.objects.filter(user_id= user_id).earliest('date').cookie_consent
    except:
        return redirect('/cookie_consent')
    response = requests.get('https://api.imgflip.com/get_memes')
    response_data = json.loads(response.content)
    url_data = ([x['url'] for x in response_data['data']['memes']])
    data = {'session_data': [f'{x}:{y}' for x, y in request.session.items()], 'url_data': random.sample(url_data, 5)}
    if consent:
        return render(request, 'dashboard.html', data)
    else:
        return redirect('/user_login',err_msg='You have been logged out and cannot go further.')

@csrf_protect
def cookie_consent(request):
    if request.method == 'GET':
        return render(request, 'cookie_consent.html')
    if 'accept' in request.POST:
        user = request.user.username
        user_id = User.objects.get(username=user).id
        consent = user_cookie_consent.objects.create(user= request.user,cookie_consent= True)
        return redirect('/dashboard')
    elif 'decline' in request.POST:
        try :
            logout(request.user)
        except:
            return redirect('/user_login',err_msg= "You can't go any further")
