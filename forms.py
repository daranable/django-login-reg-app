from django import forms
from django.forms import ModelForm
from .models import User
import bcrypt
import base64
import hashlib
import re
valid_password = re.compile(
    r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[$@$!%*#?&])[A-Za-z\d$@$!%*#?&]{8,}$"
)
class LoginForm(forms.Form):
    email= forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput())

    def clean(self):
        cleaned_data = super(LoginForm, self).clean()
        cemail = cleaned_data.get('email')
        cpass = cleaned_data.get('password')

        try:
            user = User.objects.get(email=cemail)
            if not bcrypt.checkpw(base64.b64encode(hashlib.sha256(cpass).digest()), user.password.encode()):
                raise forms.ValidationError('Username or Password is incorrect')
        except:
            raise forms.ValidationError('Username or Password is incorrect')

class RegistrationForm(ModelForm):
    confirm_password = forms.CharField(widget=forms.PasswordInput())
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password']
        widgets = {
            'password': forms.PasswordInput(),
        }

    def clean(self):
        cleaned_data = super(RegistrationForm, self).clean()
        password = cleaned_data.get('password')
        conf_password = cleaned_data.get('confirm_password')
        first = cleaned_data.get('first_name')
        last = cleaned_data.get('last_name')

        if len(first) < 2:
            self.add_error('first_name', 'Name must be longer than 1 character')
        if len(last) < 2:
            self.add_error('last_name', 'Name must be longer than 1 character')
        if password != conf_password:
            self.add_error('password', 'Password fields must match')
            self.add_error('confirm_password', 'Password fields must match')
        if not valid_password.match(password):
            self.add_error('password', 'Password must be at least 10 characters, have at least one upper case, on lower case, and one number')

    def save(self, commit=True):
        instance = super(RegistrationForm, self).save(commit=False)
        # We use sha256 so we don't have bcrypt pw length limit of 72 characters.
        instance.password = bcrypt.hashpw(base64.b64encode(hashlib.sha256(instance.password).digest()), bcrypt.gensalt())
        if commit:
            instance.save()
        return instance
