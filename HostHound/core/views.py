from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.views import LoginView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import *
from django.views.decorators.http import require_http_methods
from django.urls import reverse_lazy, reverse
from django.db import IntegrityError, OperationalError
from .forms import *
from .models import *
import xml.etree.ElementTree as ET


class RegisterView(CreateView):
    template_name = 'registration/register.html'
    form_class = RegisterForm
    success_url = reverse_lazy('login')
    

class UserLoginView(LoginView):
    template_name = 'registration/login.html'
    form_class = LoginForm
    success_url = reverse_lazy('/')
    
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard')
        return super().dispatch(request, *args, **kwargs) 
    

def UserLogoutView(request):
    logout(request)
    return redirect('login') 
    
    
class DashboardView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            self.node_name = 'workspace'
            self.nodes = Workspace.objects.filter(user=request.user)
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        self.form = WorkspaceForm()
        return render(request, 
                      'dashboard/node.html', 
                      {'node_name': self.node_name, 
                        'form': self.form,
                        'nodes': self.nodes
                    })
        
    def post(self, request, *args, **kwargs):
        self.form = WorkspaceForm(request.POST)
        if self.form.is_valid():
            try:
                workspace = self.form.save(commit=False)
                workspace.user = request.user
                workspace.save()
                messages.success(request, "Workspace added successfully")
            except Exception as e:
                messages.error(request, f"An error occured : {e}")
        return render(request, 
                      'dashboard/node.html', 
                      {'node_name': self.node_name, 
                        'form': self.form,
                        'nodes': self.nodes
                    })
        
        
class WorkspaceDetailView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            try:
                self.node_name = 'host'
                self.parent_object = get_object_or_404(Workspace, id=kwargs.get('pk'), user=request.user)
                self.nodes = Host.objects.filter(workspace=self.parent_object)
            except Http404 as e:
                messages.error(request, f"Object not found : {e}")
                self.nodes = []
                self.parent_object = False
            except Exception as e:
                messages.error(request, f"An error occured : {e}")
        return super().dispatch(request, *args, **kwargs)
    
    def get(self, request, *args, **kwargs):
        self.form = HostForm()
        return render(request, 
                      'dashboard/node.html', 
                      {'node_name': self.node_name, 
                        'form': self.form,
                        'back': request.META.get('HTTP_REFERER', '/'),
                        'workspace_id': kwargs.get('pk'),
                        'nodes': self.nodes
                    })
        
    def post(self, request, *args, **kwargs):
        self.form = HostForm(request.POST)
        if self.form.is_valid():
            try:
                if self.parent_object:
                    host = self.form.save(commit=False)
                    host.workspace = self.parent_object
                    host.save()
                    messages.success(request, "Host added successfully")
            except Exception as e:
                messages.error(request, f"An error occured : {e}")
        return render(request, 
                      'dashboard/node.html', 
                      {'node_name': self.node_name, 
                        'form': self.form,
                        'back': request.META.get('HTTP_REFERER', '/'),
                        'workspace_id': kwargs.get('pk'),
                        'nodes': self.nodes
                    })
        
        
class HostDetailView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            try:
                self.node_name = 'port'
                self.parent_object = get_object_or_404(Host, id=kwargs.get('pk'))
                self.workspace_id = -1
                if self.parent_object.workspace.user == request.user:
                    self.nodes = Port.objects.filter(host=self.parent_object)
                    self.workspace_id = self.parent_object.workspace.id
                else:
                    messages.error(request, f"Host does not belongs to this user")
                    self.nodes = []
                    self.parent_object = False
            except Http404 as e:
                messages.error(request, f"Object not found : {e}")
                self.nodes = []
                self.parent_object = False
            except Exception as e:
                messages.error(request, f"An error occured : {e}")
        return super().dispatch(request, *args, **kwargs)
    
    def get(self, request, *args, **kwargs):
        self.form = PortForm()
        return render(request, 
                      'dashboard/node.html', 
                      {'node_name': self.node_name, 
                        'form': self.form,
                        'back': request.META.get('HTTP_REFERER', '/'),
                        'workspace_id': self.workspace_id,
                        'nodes': self.nodes
                    })

    def post(self, request, *args, **kwargs):
        self.form = PortForm(request.POST)
        if self.form.is_valid():
            try:
                if self.parent_object:
                    if self.parent_object.workspace.user == request.user:
                        port = self.form.save(commit=False)
                        port.host = self.parent_object
                        port.save()
                        messages.success(request, "Port added successfully")
            except Exception as e:
                messages.error(request, f"An error occured : {e}")
        return render(request, 
                      'dashboard/node.html', 
                      {'node_name': self.node_name, 
                        'form': self.form,
                        'back': request.META.get('HTTP_REFERER', '/'),
                        'workspace_id': self.workspace_id,
                        'nodes': self.nodes
                    })
                
                
class PortDetailView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            try:
                self.workspace_id = -1
                self.node_name = 'endpoint'
                self.parent_object = get_object_or_404(Port, id=kwargs.get('pk'))
                if self.parent_object.host.workspace.user == request.user:
                    self.nodes = Endpoint.objects.filter(port=self.parent_object)
                    self.workspace_id = self.parent_object.host.workspace.id
                else:
                    messages.error(request, f"Port does not belongs to this user")
                    self.nodes = []
                    self.parent_object = False
            except Http404 as e:
                messages.error(request, f"Object not found : {e}")
                self.nodes = []
                self.parent_object = False
            except Exception as e:
                messages.error(request, f"An error occured : {e}")
        return super().dispatch(request, *args, **kwargs)
    
    def get(self, request, *args, **kwargs):
        self.form = EndpointForm(instance=self.parent_object)
        return render(request, 
                      'dashboard/node.html', 
                      {'node_name': self.node_name, 
                        'form': self.form,
                        'back': request.META.get('HTTP_REFERER', '/'),
                        'workspace_id': self.workspace_id,
                        'nodes': self.nodes
                    })

    def post(self, request, *args, **kwargs):
        self.form = EndpointForm(request.POST)
        if self.form.is_valid():
            try:
                if self.parent_object:
                    if self.parent_object.host.workspace.user == request.user:
                        endpoint = self.form.save(commit=False)
                        endpoint.port = self.parent_object
                        endpoint.save()
                        messages.success(request, "Endpoint added successfully")
            except Exception as e:
                messages.error(request, f"An error occured : {e}")
        self.form = EndpointForm(instance=self.parent_object)
        return render(request, 
                      'dashboard/node.html', 
                      {'node_name': self.node_name, 
                        'form': self.form,
                        'back': request.META.get('HTTP_REFERER', '/'),
                        'workspace_id': self.workspace_id,
                        'nodes': self.nodes
                    })

        
class WorkspaceUpdateView(LoginRequiredMixin, UpdateView):
    model = Workspace
    form_class = WorkspaceForm
    template_name = 'dashboard/node.html'
    success_url = reverse_lazy('dashboard')
    
    def get_object(self, queryset=None):
        try:    
            workspace = get_object_or_404(Workspace, pk=self.kwargs.get('pk'))
            if workspace.user != self.request.user:
                messages.error(self.request, f"Workspace does not belong to this user")
                return redirect('dashboard')
        except Http404 as e:
            messages.error(self.request, f"Object not found {e}")
            return redirect('dashboard')
        except Exception as e:
            messages.error(f"An error occured : {e}")
            return redirect('dashboard')
        return workspace
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['nodes'] = Workspace.objects.filter(user=self.request.user)
        context['node_name'] = 'workspace'
        context['back'] = self.request.META.get('HTTP_REFERER', '/'),
        context['workspace_id'] = kwargs.get('pk')
        return context
    
    def get(self, request, *args, **kwargs):
        return redirect('dashboard')
    
    def form_valid(self, form):
        try:
            response = super().form_valid(form)
            self.extra_context = self.get_context_data()
            messages.success(self.request, "Workspace updated successfully")
            return response
        except Exception as e:
            messages.error(self.request, f"An error occured : {e}")
            self.extra_context = self.get_context_data()
            return self.form_invalid(form)

    
class HostUpdateView(LoginRequiredMixin, UpdateView):
    model = Host
    form_class = HostForm
    template_name = 'dashboard/node.html'
    
    def get_success_url(self):
        host = self.get_object()
        return reverse_lazy('workspace_detail', kwargs={'pk': host.workspace.id})
    
    def get_object(self, queryset=None):
        try:    
            host = get_object_or_404(Host, pk=self.kwargs.get('pk'))
            if host.workspace.user != self.request.user:
                messages.error(self.request, f"Host does not belong to this user")
                return redirect('dashboard')
        except Http404 as e:
            messages.error(self.request, f"Object not found {e}")
            return redirect('dashboard')
        except Exception as e:
            messages.error(f"An error occured : {e}")
            return redirect('workspace_detail', pk=host.workspace.id)
        return host
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        host = self.get_object()
        context['nodes'] = Host.objects.filter(workspace=host.workspace)
        context['node_name'] = 'host'
        context['back'] = self.request.META.get('HTTP_REFERER', '/'),
        context['workspace_id'] = host.workspace.id
        return context
    
    def get(self, request, *args, **kwargs):
        host = self.get_object()
        return redirect('workspace_detail', pk=host.workspace.id)
    
    def form_valid(self, form):
        try:
            response = super().form_valid(form)
            self.extra_context = self.get_context_data()
            messages.success(self.request, "Host updated successfully")
            return response
        except Exception as e:
            messages.error(self.request, f"An error occured : {e}")
            self.extra_context = self.get_context_data()
            return self.form_invalid(form)
    
    
class PortUpdateView(LoginRequiredMixin, UpdateView):
    model = Port
    form_class = PortForm
    template_name = 'dashboard/node.html'
    
    def get_success_url(self):
        port = self.get_object()
        return reverse_lazy('host_detail', kwargs={'pk': port.host.id})
    
    def get_object(self, queryset=None):
        try:    
            port = get_object_or_404(Port, pk=self.kwargs.get('pk'))
            if port.host.workspace.user != self.request.user:
                messages.error(self.request, f"Port does not belong to this user")
                return redirect('dashboard')
        except Http404 as e:
            messages.error(self.request, f"Object not found {e}")
            return redirect('dashboard')
        except Exception as e:
            messages.error(f"An error occured : {e}")
            return redirect('host_detail', pk=port.host.id)
        return port
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        port = self.get_object()
        context['nodes'] = Port.objects.filter(host=port.host)
        context['node_name'] = 'port'
        context['back'] = self.request.META.get('HTTP_REFERER', '/'),
        context['workspace_id'] = port.host.workspace.id
        return context
    
    def get(self, request, *args, **kwargs):
        port = self.get_object()
        return redirect('host_detail', pk=port.host.id)
    
    def form_valid(self, form):
        try:
            response = super().form_valid(form)
            self.extra_context = self.get_context_data()
            messages.success(self.request, "Port updated successfully")
            return response
        except Exception as e:
            messages.error(self.request, f"An error occured : {e}")
            self.extra_context = self.get_context_data()
            return self.form_invalid(form)
    
    
class EndpointUpdateView(LoginRequiredMixin, UpdateView):
    model = Endpoint
    form_class = EndpointForm
    template_name = 'dashboard/node.html'
    
    def get_success_url(self):
        endpoint = self.get_object()
        return reverse_lazy('port_detail', kwargs={'pk': endpoint.port.id})
    
    def get_object(self, queryset=None):
        try:    
            endpoint = get_object_or_404(Endpoint, pk=self.kwargs.get('pk'))
            if endpoint.port.host.workspace.user != self.request.user:
                messages.error(self.request, f"Endpoint does not belong to this user")
                return redirect('dashboard')
        except Http404 as e:
            messages.error(self.request, f"Object not found {e}")
            return redirect('dashboard')
        except Exception as e:
            messages.error(f"An error occured : {e}")
            return redirect('port_detail', pk=endpoint.port.id)
        return endpoint
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        endpoint = self.get_object()
        context['nodes'] = Endpoint.objects.filter(port=endpoint.port)
        context['node_name'] = 'endpoint'
        context['back'] = self.request.META.get('HTTP_REFERER', '/'),
        context['workspace_id'] = endpoint.port.host.workspace.id
        return context
    
    def get(self, request, *args, **kwargs):
        endpoint = self.get_object()
        return redirect('port_detail', pk=endpoint.port.id)
    
    def form_valid(self, form):
        try:
            response = super().form_valid(form)
            self.extra_context = self.get_context_data()
            messages.success(self.request, "Endpoint updated successfully")
            return response
        except Exception as e:
            messages.error(self.request, f"An error occured : {e}")
            return self.form_invalid(form)
    
    
class WorkspaceDeleteView(LoginRequiredMixin, DeleteView):
    model = Workspace
    template_name = 'dashboard/node.html'
    
    def delete(self, request, *args, **kwargs):
        try:
            self.object = self.get_object()
            if self.object.user == request.user:
                self.object.delete()
                messages.success(request, f"Workspace deleted successfully")
            else:
                messages.error(request, "Workspace does not belong to this user")
            return redirect('dashboard') 
        except Http404 as e:
            messages.error(request, f"Object does not exists : {e}")
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f"An error occured : {e}")
            return redirect('dashboard')

    def get(self, request, *args, **kwargs):
        return self.delete(request)


class HostDeleteView(LoginRequiredMixin, DeleteView):
    model = Host
    template_name = 'dashboard/node.html'

    def delete(self, request, *args, **kwargs):
        try:
            self.object = self.get_object()
            if self.object.workspace.user == request.user:
                workspace = self.object.workspace
                self.object.delete()
                messages.success(request, f"Host deleted successfully")
                return redirect(reverse('workspace_detail', kwargs={'pk': workspace.id}))
            else:
                messages.error(request, f"Host does not belongs to this user")    
                return redirect('dashboard')
        except Http404 as e:
            messages.error(request, f"Object does not exists : {e}")
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f"An error occured : {e}")
            return redirect(reverse('workspace_detail', kwargs={'pk': workspace.id}))
    
    def get(self, request, *args, **kwargs):
        return self.delete(request)


class PortDeleteView(LoginRequiredMixin, DeleteView):
    model = Port
    template_name = 'dashboard/node.html'
    
    def delete(self, request, *args, **kwargs):
        try:
            self.object = self.get_object()
            if self.object.host.workspace.user == request.user:
                host = self.object.host
                self.object.delete()
                messages.success(request, f"Port deleted successfully")
                return redirect(reverse('host_detail', kwargs={'pk': host.id}))
            else:
                messages.error(request, f"Port does not belongs to this user")    
                return redirect('dashboard')
        except Http404 as e:
            messages.error(request, f"Object does not exists : {e}")
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f"An error occured : {e}")
            return redirect(reverse('host_detail', kwargs={'pk': host.id}))
    
    def get(self, request, *args, **kwargs):
        return self.delete(request)


class EndpointDeleteView(LoginRequiredMixin, DeleteView):
    model = Endpoint
    template_name = 'dashboard/node.html'
    
    def delete(self, request, *args, **kwargs):
        try:
            self.object = self.get_object()
            if self.object.port.host.workspace.user == request.user:
                port = self.object.port
                self.object.delete()
                messages.success(request, f"Endpoint deleted successfully")
                return redirect(reverse('port_detail', kwargs={'pk': port.id}))
            else:
                messages.error(request, f"Endpoint does not belongs to this user")    
                return redirect('dashboard')
        except Http404 as e:
            messages.error(request, f"Object does not exists : {e}")
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f"An error occured : {e}")
    
    def get(self, request, *args, **kwargs):
        return self.delete(request)
    
    
class NmapUploadView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        return redirect(reverse('workspace_detail', kwargs={'pk': kwargs.get('pk')}))
    
    def post(self, request, *args, **kwargs):
        form = NmapUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                workspace = get_object_or_404(Workspace, id=kwargs.get('pk'), user=request.user)
                uploaded_file = request.FILES['file']
                tree = ET.parse(uploaded_file)
                root = tree.getroot()
                
                for host in root.findall('host'):
                    if host.find('status').attrib.get('state', 'unknown') == 'up':
                        ipv4_address = host.find('address').attrib.get('addr', None)
                        hostname = None
                        if host.find('hostnames') is not None:
                            hostname = host.find('hostnames').find('hostname')
                            if hostname is not None:
                                hostname = hostname.attrib.get('name', None)
                        host_instance, created = Host.objects.get_or_create(
                            workspace = workspace,
                            ipv4_address = ipv4_address,
                            hostname = hostname
                        )
                                
                    for port in host.findall(".//port"):
                        port_number = int(port.attrib.get('portid', -1))
                        service = port.find('service').attrib.get('name', None)
                        version = port.find('service').attrib.get('product', '') + ' ' + port.find('service').attrib.get('version','')
                        
                        if port_number > 0:
                            Port.objects.get_or_create(
                                host = host_instance,
                                port_no = port_number,
                                service = service,
                                version = version
                            )
                messages.success(request, f"Successfully updated data in current workspace")
                return redirect(reverse('workspace_detail', kwargs={'pk': kwargs.get('pk')}))
            except Http404:
                messages.error(request, f"No workspace found")
                return redirect('dashboard')
            except ET.ParseError:
                messages.error(request, f"Invalid XML format. Please check the file.")
                return redirect(reverse('workspace_detail', kwargs={'pk': kwargs.get('pk')}))
            except Exception as e:
                messages.error(request, f"An error occured : {e}")
                return redirect(reverse('workspace_detail', kwargs={'pk': kwargs.get('pk')}))


class WorkspaceVisualizationView(LoginRequiredMixin, DetailView):
    model = Workspace
    template_name = 'dashboard/network.html'
    context_object_name = 'workspace'

    def get_object(self, queryset=None):
        workspace_id = self.kwargs.get('pk')
        try:
            workspace = get_object_or_404(Workspace, id=workspace_id, user=self.request.user)
            return workspace
        except Http404:
            raise Http404("Workspace not found or you do not have permission to view this workspace.")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        workspace = context['workspace']
        
        nodes = []
        edges = []

        for host in workspace.hosts.all():
            title = f"Ip Address: {host.ipv4_address}\n"
            title += f"Hostname: {host.hostname}\n"
            title += f"Reviewed: {host.reviewed}\n"
            title += f"Exploitable: {host.exploitable}\n"
            title += f"Notes: {host.notes}\n"
            nodes.append({
                'id': f"host_{host.id}",
                'label': host.hostname if host.hostname else host.ipv4_address,
                'group': 'host',
                'title': title
            })
            
            for port in host.ports.all():
                title = f"Port Number: {port.port_no}\n"
                title += f"Service: {port.service}\n"
                title += f"Version: {port.version}\n"
                title += f"Reviewed: {host.reviewed}\n"
                title += f"Exploitable: {host.exploitable}\n"
                title += f"Notes: {host.notes}\n"
                nodes.append({
                    'id': f"port_{port.id}",
                    'label': f"Port {port.port_no}",
                    'group': 'port',
                    'title': title
                })

                edges.append({
                    'from': f"host_{host.id}",
                    'to': f"port_{port.id}"
                })

                for endpoint in port.endpoints.all():
                    title = f"Endpoint: {endpoint.endpoint_name}\n"
                    title += f"Status code: {endpoint.status_code}\n"
                    title += f"Reviewed: {endpoint.reviewed}\n"
                    title += f"Exploitable: {endpoint.exploitable}\n"
                    title += f"Notes: {endpoint.notes}\n"
                    
                    nodes.append({
                        'id': f"endpoint_{endpoint.id}",
                        'label': endpoint.endpoint_name,
                        'group': 'endpoint',
                        'title': title
                    })
                    
                    for sub_endpoint in endpoint.endpoints.all():
                        edges.append({
                            'from': f"endpoint_{endpoint.id}",
                            'to': f"endpoint_{sub_endpoint.id}"
                        })
                      
                for endpoint in port.endpoints.all():
                    if not list(filter(lambda x: x['to'] == f"endpoint_{endpoint.id}", edges)):
                        edges.append({
                        'from': f"port_{port.id}",
                        'to': f"endpoint_{endpoint.id}"
                        })
                        
        context['graph_data'] = {
            'nodes': nodes,
            'edges': edges,
        }
        return context