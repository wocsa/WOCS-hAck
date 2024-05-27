# Register your models here.

from django.contrib import admin
from .models import (
    UserProfile,
    Tutorial,
    Comment,
    TextContent,
    PictureContent
)


admin.site.register(UserProfile)
admin.site.register(Tutorial)
admin.site.register(Comment)
admin.site.register(TextContent)
admin.site.register(PictureContent)
