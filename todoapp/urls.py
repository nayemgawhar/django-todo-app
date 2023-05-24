from django.urls import path
from .views import deleteTodo, completeTodo, allTodos, changePassword, forgetPasswordConfirm, updateTodo, forgetPassword, index, login, register, logout
from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView

urlpatterns = [
    path('', index, name="index"),
    path('complete-todo/<int:id>/', completeTodo, name="completeTodo"),
    path('delete-todo/<int:id>/', deleteTodo, name="deleteTodo"),
    path('update-todo/<str:id>/', updateTodo, name="updateTodo"),
    path('login/', login, name="login"),
    path('register/', register, name="register"),
    path('logout/', logout, name="logout"),

    path('forget_password/', forgetPassword, name="forget_password"),
    path('password_reset_confirm/', forgetPasswordConfirm,
         name="password_reset_confirm"),

    path('all-todos/', allTodos, name="all-todos"),
    path('change-password/<int:id>/', changePassword, name="change-password"),


    path('password-reset/',
         PasswordResetView.as_view(
             template_name='users/password_reset.html',
             html_email_template_name='users/password_reset_email.html'
         ),
         name='password-reset'
         ),
    path('password-reset/done/', PasswordResetDoneView.as_view(
        template_name='users/password_reset_done.html'), name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(
        template_name='users/password_reset_confirm.html'), name='password_reset_confirm'),
    path('password-reset-complete/', PasswordResetCompleteView.as_view(
        template_name='users/password_reset_complete.html'), name='password_reset_complete'),
]
