# Generated by Django 5.1.5 on 2025-03-01 14:58

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_alter_endpoint_edges'),
    ]

    operations = [
        migrations.AlterField(
            model_name='endpoint',
            name='edges',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='endpoints', to='core.endpoint'),
        ),
    ]
