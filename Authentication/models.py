from django.db import models
from django.utils import timezone
from django.core.validators import EmailValidator
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self, email, name, password=None):
      if not email:
          raise ValueError('User must have an email address')

      user = self.model(
          email=self.normalize_email(email),
          name=name,
      )
      user.set_password(password)
      user.save(using=self._db)
      return user
    

    def create_superuser(self, email, name, password=None):
        user = self.create_user(
            email=email,
            password=password,
            name=name,
            
        )
        user.is_admin = True
        user.save(using=self._db)
        return user



class User(AbstractBaseUser):
    email = models.EmailField(verbose_name='Email',max_length=255, unique=True,validators=[EmailValidator()],)
    name = models.CharField(max_length=150)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']


    def __str__(self):
      return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
    

class OTP(models.Model):
    email = models.EmailField(
        verbose_name="email address", max_length=255, validators=[EmailValidator()]
    )
    otp = models.CharField(max_length=4, blank=True, null=True)
    time = models.DateTimeField(default=timezone.now)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.email