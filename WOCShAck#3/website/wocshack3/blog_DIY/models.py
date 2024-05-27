from django.db import models
from django.contrib.auth.models import User
from django.core.validators import FileExtensionValidator
import uuid


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    profile_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    profile_picture = models.ImageField(
        upload_to="uploads/%Y/%m/%d/", validators=[
            FileExtensionValidator(allowed_extensions=["png", "jpeg", "jpg"])
        ],
        default="default.png",
    )
    bio = models.CharField(max_length=500, blank=True)

    def __str__(self):
        return self.user.username


class Tutorial(models.Model):
    author_user = models.ForeignKey(
        to=UserProfile, on_delete=models.CASCADE, related_name="tutorial"
    )
    title = models.CharField(max_length=500)
    creation_date = models.DateTimeField(auto_now_add=True)
    published = models.BooleanField(default=False)

    @property
    def content_sorted(self):
        all_content: list = list(self.text_content.all()) + list(self.picture_content.all())
        return sorted(all_content, key=lambda x: x.creation_date)

    def __str__(self):
        return self.title

    def comment_count(self):
        return self.comment.count()


class TextContent(models.Model):
    tutorial_related = models.ForeignKey(
        to=Tutorial, on_delete=models.CASCADE, related_name="text_content"
    )
    bodyline = models.CharField(max_length=8000, blank=False)
    creation_date = models.DateTimeField(auto_now_add=True)

    def get_model_name(self):
        return 'textcontent'


class PictureContent(models.Model):
    tutorial_related = models.ForeignKey(
        to=Tutorial, on_delete=models.CASCADE, related_name="picture_content"
    )
    picture = models.ImageField(
        upload_to="uploads/%Y/%m/%d/", validators=[
            FileExtensionValidator(allowed_extensions=["png", "jpeg", "jpg"])
        ]
    )
    creation_date = models.DateTimeField(auto_now_add=True)

    def get_model_name(self):
        return 'picturecontent'


class Comment(models.Model):
    author_user = models.ForeignKey(
        to=UserProfile, on_delete=models.CASCADE, related_name="comment"
    )
    tutorial_related = models.ForeignKey(
        to=Tutorial, on_delete=models.CASCADE, related_name="comment"
    )
    bodyline = models.CharField(max_length=4000, blank=False)
    creation_date = models.DateTimeField(auto_now_add=True)
