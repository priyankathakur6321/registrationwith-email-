from django.conf.urls import url
from django.urls import path


from . import views
from .views import UserList, UpdateApi, ContentCreateApi, ContentRenewCreateApi, ContentCreateApiList

urlpatterns = [

    url(r'^login/$',
        views.UserLoginAPIView.as_view(),
        name='login'),

    url(r'^register/$',
        views.UserRegistrationAPIView.as_view(),
        name='register'),

    url(r'^verify/(?P<verification_key>.+)/$',
        views.UserEmailVerificationAPIView.as_view(),
        name='email_verify'),

    url(r'^password_reset/$',
        views.PasswordResetAPIView.as_view(),
        name='password_change'),

    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.PasswordResetConfirmView.as_view(),
        name='password_reset_confirm'),

    url(r'^user-profile/$',
        views.UserProfileAPIView.as_view(),
        name='user_profile'),

    url('UserList/', UserList.as_view()),
    path('update/<int:pk>/', UpdateApi.as_view()),
    path('delete/<str:pk>/',views.DeleteApi,name="delete"),
    url('ContentCreateApi/', ContentCreateApi.as_view()),
    url('ContentCreateApiList/', ContentCreateApiList.as_view()),

    path('ContentRenewCreateApi/<int:pk>/', views.ContentRenewCreateApi.as_view()),
    path('ContentDestroyCreateApi/<str:pk>/', views.ContentDestroyCreateApi, name="delete"),

]
