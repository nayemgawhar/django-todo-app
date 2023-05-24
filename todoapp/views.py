from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from email.message import EmailMessage
from django import forms
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as authLogin, logout as authLogout
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.db.models.query_utils import Q
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from .models import Todo


@login_required
def index(request):
    if request.method == 'POST':
        text = request.POST.get("text").strip()
        if text:
            Todo.objects.create(text=text, user=request.user)
        return redirect('/')

    todos = Todo.objects.filter(user=request.user)
    context = {
        'todos': todos
    }
    return render(request, 'todoapp/index.html', context)


@login_required
def allTodos(request):
    todos = Todo.objects.all()
    context = {
        'todos': todos
    }
    return render(request, 'todoapp/all_todo.html', context)


@login_required
def deleteTodo(request, id):
    get_object_or_404(Todo, id=id, user=request.user).delete()
    return redirect('/')


@login_required
def completeTodo(request, id):
    Todo.objects.filter(id=id).update(is_complete=1)
    messages.add_message(request, messages.SUCCESS,
                         "Successfully Task completed.")
    return redirect('/')


@login_required
def updateTodo(request, id):
    todo = Todo.objects.get(id=id)
    if request.method == 'POST':
        text = request.POST.get("text").strip()
        Todo.objects.filter(id=id).update(text=text)
        messages.add_message(request, messages.SUCCESS,
                             "Successfully Task updated.")
        return redirect('/')
    context = {
        'todo': todo
    }
    return render(request, 'todoapp/update.html', context)


def login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            authLogin(request, user)
            messages.add_message(request, messages.SUCCESS,
                                 "Successfully Logged in.")
            return redirect('index')
        else:
            messages.add_message(request, messages.ERROR,
                                 "Credentials are not valid.")
            return redirect('login')
    if request.user.is_authenticated:
        return redirect('index')
    else:
        return render(request, 'todoapp/login.html')


def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            messages.add_message(request, messages.ERROR,
                                 "Passwords didn't match")
            return redirect("register")

        user = User.objects.create_user(
            first_name=first_name, last_name=last_name, username=username, email=email, password=password1)

        authLogin(request, user)
        return redirect('index')
    if request.user.is_authenticated:
        return redirect('index')
    else:
        return render(request, 'todoapp/register.html')


@login_required
def logout(request):
    authLogout(request)
    return redirect('login')


def forgetPassword(request):
    if request.method == 'POST':
        email = request.POST.get("email")
        associated_user = User.objects.filter(Q(email=email)).first()
        if associated_user:
            subject = "Password Reset request"
            message = render_to_string("todoapp/email/password_reset_email.html", {
                'user': associated_user,
                'domain': settings.DOMAIN_HOSTS,
                'uid': urlsafe_base64_encode(force_bytes(associated_user.pk)),
                'token': default_token_generator.make_token(associated_user),
                "protocol": 'https' if request.is_secure() else 'http'
            })
            email = EmailMessage(subject, message, [associated_user.email])
            if email.send_mail():
                messages.add_message(request, messages.SUCCESS,
                                     """
                    <h2>Password reset sent</h2><hr>
                    <p>
                        We've emailed you instructions for setting your password, if an account exists with the email you entered. 
                        You should receive them shortly.<br>If you don't receive an email, please make sure you've entered the address 
                        you registered with, and check your spam folder.
                    </p>
                    """
                                     )
            else:
                messages.add_message(
                    request, messages.ERROR, "Problem sending reset password email, <b>SERVER PROBLEM</b>")
        return redirect('login')

    return render(request, 'todoapp/forget_password.html')


def forgetPasswordConfirm(request):
    return "Hello"


@login_required
def changePassword(request, id):
    user = User.objects.get(id=id)
    if request.method == 'POST':
        password = request.POST.get("password")
        User.objects.filter(id=id).update(
            password=make_password(password, salt='pbkdf2_sha256', hasher='default'))
        messages.add_message(request, messages.SUCCESS,
                             "Successfully password updated.")
        return redirect('index')
    context = {
        'user': user
    }
    return render(request, 'todoapp/change_password.html', context)
