from django.db import models
from django.contrib.auth.models import AbstractUser


class Utilisateur(AbstractUser):

    lesRoles = (
        ('patient', 'patient'),
        ("medecin", 'medecin'),
        ("responsable", "responsable"),
    )

    role = models.CharField(max_length=30,
                            choices=lesRoles,
                            verbose_name='Rôle', null=True)


class medecinPatient(models.Model):
    idPatient = models.ForeignKey(Utilisateur,
                                  null=True,
                                  on_delete=models.CASCADE,
                                  related_name='patientMedecin',
                                  unique=True)
    idMedecin = models.ForeignKey(Utilisateur,
                                  null=True,
                                  on_delete=models.CASCADE,
                                  related_name='medecinPatient')
