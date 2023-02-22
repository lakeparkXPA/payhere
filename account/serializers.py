from rest_framework import serializers

from account.models import User
from tools import make_token


class UserLogin(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

    def to_representation(self, instance):
        data = super().to_representation(instance)

        if instance.pk:
            return {'token': make_token(instance.pk), 'refresh_token': make_token(instance.pk, auth='refresh', hours=6)}
        return data
