from django.urls import path
from .views import *

urlpatterns = [
    path('', DashboardView.as_view(), name='/'),
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', UserLogoutView, name='logout'),
    path('workspace/<int:pk>/', WorkspaceDetailView.as_view(), name="workspace_detail"),
    path('workspace-edit/<int:pk>/', WorkspaceUpdateView.as_view(), name='workspace_edit'),
    path('workspace-delete/<int:pk>/', WorkspaceDeleteView.as_view(), name="workspace_delete"),
    path('host/<int:pk>/', HostDetailView.as_view(), name="host_detail"),
    path('host-edit/<int:pk>/',  HostUpdateView.as_view(), name='host_edit'),
    path('host-delete/<int:pk>/',  HostDeleteView.as_view(), name='host_delete'),
    path('port/<int:pk>/', PortDetailView.as_view(), name="port_detail"),
    path('port-edit/<int:pk>/',  PortUpdateView.as_view(), name='port_edit'),
    path('port-delete/<int:pk>/',  PortDeleteView.as_view(), name='port_delete'),
    path('endpoint-edit/<int:pk>/',  EndpointUpdateView.as_view(), name='endpoint_edit'),
    path('endpoint-delete/<int:pk>/',  EndpointDeleteView.as_view(), name='endpoint_delete'),
    path('upload-nmap/<int:pk>/', NmapUploadView.as_view(), name='upload_nmap'),
    path('workspace-visualize/<int:pk>/', WorkspaceVisualizationView.as_view(), name='workspace_visualize')
]
