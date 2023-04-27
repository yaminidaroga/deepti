from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.http import Http404
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.contrib.sites.shortcuts import get_current_site

from boards.forms import CreateBoardForm
from .forms import UserRegistrationForm, UserLoginForm, EditProfileForm
from .models import User, Follow
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages

from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model

User = get_user_model()


def user_register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            check_user = User.objects.filter(
                Q(username=data['username']) | Q(email=data['email'])
            )
            if not check_user:
                # create a new user with is_active=False
                user = User.objects.create_user(
                    data['email'], data['username'], data['password']
                )
                user.is_active=False
                user.save()
                # generate a token for email verification
                token = default_token_generator.make_token(user)
                # send email with verification link
                subject = 'Activate Your Account'
                message = render_to_string('activate_email.html', {
                    'user': user,
                    'domain': get_current_site(request),
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': token,
                })
                send_mail(
                    subject, message, 'noreply@example.com', [data['email']], fail_silently=False,
                )
                # redirect to the verification page
                messages.success(request, 'Thank you for signing up!\nPlease check your email and follow the instructions to activate your account.')
                return redirect('accounts:user_login')
    else:
        form = UserRegistrationForm()
    context = {'title': 'Signup', 'form': form}
    return render(request, 'register.html', context)


def activate_email(request, uidb64, token):
    try:
        # decode user id from uidb64 string
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(
            request, 'Your account has been activated!\n You can now log in using your credentials.')

        return redirect('accounts:user_login')

    else:
        messages.success(
            request, 'Sorry, the activation link is invalid or has expired.\n Please request a new activation link or contact the support team for assistance.')

        return redirect('accounts:user_login')

    

def verify_email(request):
    return render(request, 'verify_email.html')

def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            user = authenticate(
                request, username=data['username'], password=data['password']
            )
            if user is not None:
                login(request, user)
                return redirect('pinterest:home')
            else:
                return redirect(request.META.get('HTTP_REFERER'))
    else:
        form = UserLoginForm()
    context = {'title':'Login', 'form': form}
    return render(request, 'login.html', context)


def user_logout(request):
    logout(request)
    return redirect('accounts:user_login')


@login_required
def follow(request, username):
    user = get_object_or_404(User, username=username)
    check_user = Follow.objects.filter(follower=request.user, following=user)
    if user == request.user:
        raise Http404
    elif check_user.exists():
        raise Http404
    else:
        follow = Follow.objects.create(follower=request.user, following=user)
        follow.save()
    return redirect(request.META.get('HTTP_REFERER'))


@login_required
def unfollow(request, username):
    user = get_object_or_404(User, username=username)
    following = Follow.objects.filter(following=user).delete()
    return redirect(request.META.get('HTTP_REFERER'))


@login_required
def profile(request, username):
    user = get_object_or_404(User, username=username)
    boards = user.board_user.all()
    is_following = request.user.followers.filter(following=user).first()
    create_board_form = CreateBoardForm()
    context = {
        'user': user,
        'boards':boards,
        'is_following': is_following,
        'create_board_form':create_board_form
    }
    return render(request, 'profile.html', context)


@login_required
def edit_profile(request):
    if request.method == 'POST':
        form = EditProfileForm(
            request.POST, request.FILES, instance=request.user.profile
        )
        if form.is_valid():
            form.save()
            return redirect('accounts:profile', request.user.username)
    else:
        form = EditProfileForm(instance=request.user.profile)
    context = {'title': 'Edit Profile', 'form': form}
    return render(request, 'edit_profile.html', context)