from django.contrib import admin
from authentication.models import Utilisateur, medecinPatient


class colonnes(admin.ModelAdmin):
    # [field.name for field in Utilisateur._meta.get_fields()]
    list_display = ("username", "role", "email", "is_superuser",)
    # list_display = [field.name for field in Utilisateur._meta.get_fields()][1:-2]
    # search_fields = #['username','role']


admin.site.register(Utilisateur, colonnes)
admin.site.register(medecinPatient)
