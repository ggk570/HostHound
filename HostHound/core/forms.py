from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import *
import re

class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username is already taken. Please choose a different one.")
        return username
    
    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        if len(password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'\d', password):
            raise forms.ValidationError("Password must contain at least one number.")
        if not re.search(r'[A-Z]', password):
            raise forms.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[!@#₹$%^&*(),.?":{}|<>]', password):
            raise forms.ValidationError("Password must contain at least one special character.")
        return password

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 != password2:
            raise forms.ValidationError("Passwords do not match. Please try again.")
        return password1
    
    
class LoginForm(AuthenticationForm):
    class Meta:
        model = User
        fields = ['username', 'password']


class PlaceHolder:
    placeholders = {
        'name' : 'Workspace Name',
        'description' : 'Workspace Description',
        'hostname' : 'Host Name',
        'ipv4_address' : 'Ip Address',
        'port_no' : 'Port Number',
        'service' : 'Service Name',
        'version' : 'Service Version',
        'status_code' : 'Status Code',
        'endpoint_name' : 'Endpoint Name',
        'edges' : 'Other endpoints arising from this endpoint in comma separated format',
        'reviewed': 'True or False',
        'exploitable': 'True or False',
        'notes' : 'Notes ...'
    }

class WorkspaceForm(forms.ModelForm):
    class Meta:
        model = Workspace
        fields = ['name', 'description']
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'
            field.widget.attrs['placeholder'] = PlaceHolder.placeholders.get(field_name, "")
        
class NodeForm(forms.ModelForm):
    class Meta:
        model = Node
        fields = ['reviewed', 'exploitable', 'notes']
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if field_name in ['reviewed', 'exploitable']:
                field.widget.attrs['class'] = 'form-check-input'
                continue
            field.widget.attrs['class'] = 'form-control'
            field.widget.attrs['placeholder'] = PlaceHolder.placeholders.get(field_name, "")

        
class HostForm(NodeForm):
    class Meta:
        model = Host
        fields = ['hostname', 'ipv4_address'] + NodeForm.Meta.fields
      
        
class PortForm(NodeForm):
    class Meta:
        model = Port
        fields = ['port_no', 'service', 'version'] + NodeForm.Meta.fields
        
        
class EndpointForm(NodeForm):
    class Meta:
        model = Endpoint
        fields = ['endpoint_name', 'status_code', 'parent'] + NodeForm.Meta.fields
    
    def __init__(self, *args, **kwargs):
        port = kwargs.get('instance', None)
        super().__init__(*args, **kwargs)
        self.fields['parent'].value = 'test'
        if isinstance(port, Port):
            self.fields['parent'].queryset = Endpoint.objects.filter(port=port)
        
        
class NmapUploadForm(forms.Form):
    file = forms.FileField