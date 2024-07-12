# Верстальщик
from rest_framework import serializers
from .models import User
import string
import random


from backend.models import User, Category, Shop, ProductInfo, Product, ProductParameter, OrderItem, Order, Contact, ConfirmEmailToken


class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ('id', 'city', 'street', 'house', 'structure', 'building', 'apartment', 'user', 'phone')
        read_only_fields = ('id',)
        extra_kwargs = {
            'user': {'write_only': True}
        }


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'company', 'position', 'token')
        read_only_fields = ('id', 'token')

    def to_representation(self, instance):
        # Выводим информацию о сериализуемом пользователе
        print("Serializing user:", instance)
        return super().to_representation(instance)
    

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        # Генерируем токен и сохраняем его в поле `token`
        # user.token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
        # user.save()

        # confirmation_token = ConfirmEmailToken.objects.create(user=user)
        confirmation_token = ConfirmEmailToken.objects.create(user=user, email=user.email)
        confirmation_token.save()
        # Выводим ключ токена в консоль
        print(f"Created confirmation token: {confirmation_token.key}")
        return user
    
        

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ('id', 'name',)
        read_only_fields = ('id',)


class ShopSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shop
        fields = ('id', 'name', 'state',)
        read_only_fields = ('id',)


class ProductSerializer(serializers.ModelSerializer):
    category = serializers.StringRelatedField()

    class Meta:
        model = Product
        fields = ('name', 'category',)


class ProductParameterSerializer(serializers.ModelSerializer):
    parameter = serializers.StringRelatedField()

    class Meta:
        model = ProductParameter
        fields = ('parameter', 'value',)


class ProductInfoSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_parameters = ProductParameterSerializer(read_only=True, many=True)

    class Meta:
        model = ProductInfo
        fields = ('id', 'model', 'product', 'shop', 'quantity', 'price', 'price_rrc', 'product_parameters',)
        read_only_fields = ('id',)


class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ('id', 'product_info', 'quantity', 'order',)
        read_only_fields = ('id',)
        extra_kwargs = {
            'order': {'write_only': True}
        }


class OrderItemCreateSerializer(OrderItemSerializer):
    product_info = ProductInfoSerializer(read_only=True)


class OrderSerializer(serializers.ModelSerializer):
    ordered_items = OrderItemCreateSerializer(read_only=True, many=True)

    total_sum = serializers.IntegerField()
    contact = ContactSerializer(read_only=True)

    class Meta:
        model = Order
        fields = ('id', 'ordered_items', 'state', 'dt', 'total_sum', 'contact',)
        read_only_fields = ('id',)
