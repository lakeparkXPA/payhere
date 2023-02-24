from rest_framework import serializers
from account.models import Abook


class AbookGet(serializers.ModelSerializer):

    class Meta:
        model = Abook
        fields = ('abook_id', 'abook_time', 'amount')



class AbookGetDetail(serializers.ModelSerializer):

    class Meta:
        model = Abook
        fields = ('abook_id', 'abook_time', 'amount', 'memo')
