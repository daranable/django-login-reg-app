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
    email= forms.EmailField(widget=forms.TextInput(attrs={'class': 'mdl-textfield__input'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'mdl-textfield__input'}))

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
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'mdl-textfield__input'}))
    class Meta:
        model = User
        fields = ['name', 'email', 'password']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'mdl-textfield__input'}),
            'email': forms.TextInput(attrs={'class': 'mdl-textfield__input'}),
            'password': forms.PasswordInput(attrs={'class': 'mdl-textfield__input'}),
        }

    def clean(self):
        cleaned_data = super(RegistrationForm, self).clean()
        password = cleaned_data.get('password')
        conf_password = cleaned_data.get('confirm_password')
        cname = cleaned_data.get('name')

        if len(cname) < 2:
            self.add_error('name', 'Name must be longer than 1 character')
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
