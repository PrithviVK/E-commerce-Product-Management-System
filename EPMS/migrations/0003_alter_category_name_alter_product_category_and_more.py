# Generated by Django 5.0.7 on 2024-08-04 22:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('interview', '0002_alter_product_category'),
    ]

    operations = [
        migrations.AlterField(
            model_name='category',
            name='name',
            field=models.TextField(max_length=200),
        ),
        migrations.AlterField(
            model_name='product',
            name='category',
            field=models.TextField(max_length=200),
        ),
        migrations.AlterField(
            model_name='review',
            name='product',
            field=models.TextField(max_length=200),
        ),
    ]
