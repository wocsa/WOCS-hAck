# Generated by Django 4.2.7 on 2023-11-03 17:15

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('profile_picture', models.ImageField(upload_to='uploads/%Y/%m/%d/', validators=[django.core.validators.FileExtensionValidator(allowed_extensions=['png', 'jpeg', 'jpg'])])),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Tutorial',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=500)),
                ('creation_date', models.DateTimeField(auto_now_add=True)),
                ('author_user', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='tutorial', to='blog_DIY.userprofile')),
            ],
        ),
        migrations.CreateModel(
            name='TextContent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bodyline', models.CharField(max_length=8000)),
                ('creation_date', models.DateTimeField(auto_now_add=True)),
                ('tutorial_related', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='text_content', to='blog_DIY.tutorial')),
            ],
        ),
        migrations.CreateModel(
            name='PictureContent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('picture', models.ImageField(upload_to='uploads/%Y/%m/%d/', validators=[django.core.validators.FileExtensionValidator(allowed_extensions=['png', 'jpeg', 'jpg'])])),
                ('creation_date', models.DateTimeField(auto_now_add=True)),
                ('tutorial_related', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='picture_content', to='blog_DIY.tutorial')),
            ],
        ),
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bodyline', models.CharField(max_length=4000)),
                ('creation_date', models.DateTimeField(auto_now_add=True)),
                ('author_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='comment', to='blog_DIY.userprofile')),
                ('tutorial_related', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='comment', to='blog_DIY.tutorial')),
            ],
        ),
    ]
