from django.shortcuts import render, redirect
from .forms import LoginForm, RegistrationForm
from django.core.urlresolvers import reverse
from django.contrib import messages
from .models import User

# Create your views here.
def register(request):
    form = RegistrationForm()
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Successfully registered please log in')
            redir = reverse('auth:login')
            if 'reg_back' in request.session:
                redir = request.session['reg_back']
            return redirect(redir)
        elif 'err_back' in request.session:
            request.session['reg_form_err'] = request.POST
            return redirect(request.session['err_back'])

    context = {
        'form': form
    }
    return render(request, 'auth/register.html', context)

def login(request):
    form = LoginForm()
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user = User.objects.get(email=form.cleaned_data.get('email'))
            request.session['user'] = {'first_name': user.first_name, 'last_name': user.last_name, 'email': user.email, 'id': user.id}
            return redirect(reverse('auth:success'))
        elif 'err_back' in request.session:
            request.session['login_form_err'] = request.POST
            return redirect(request.session['err_back'])
    return render(request, 'auth/login.html', {'form': form})

def logout(request):
    if 'user' in request.session:
        del request.session['user']
        messages.success(request, 'Successfully logged out.')
    return redirect(reverse('auth:login'))

def success(request):
    context = {
        'user': request.session['user']
    }
    if 'redirect' in request.session:
        context['redirect'] = request.session['redirect']
        del request.session['redirect']
    return render(request, 'auth/success.html', context)
