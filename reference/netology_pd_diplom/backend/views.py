from distutils.util import strtobool
from rest_framework.request import Request
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import IntegrityError
from django.db.models import Q, Sum, F
from django.http import JsonResponse
from requests import get
from rest_framework.authtoken.models import Token
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from ujson import loads as load_json
from yaml import load as load_yaml, Loader
from django.contrib.auth.models import User
import random
from rest_framework import status
import string
from django.contrib.auth import get_user_model
from rest_framework import generics





from backend.models import Shop, Category, User, Product, ProductInfo, Parameter, ProductParameter, Order, OrderItem, \
    Contact, ConfirmEmailToken
from backend.serializers import UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer, \
    OrderItemSerializer, OrderSerializer, ContactSerializer
from backend.signals import new_user_registered, new_order

from django.http import HttpResponse





class HomeView(APIView):

   def get(self, request):
        return HttpResponse("Hello, this is the home page!")
   



class RegisterAccount(APIView):
    """
    Для регистрации покупателей
    """

    # Регистрация методом POST

    def post(self, request, *args, **kwargs):
        """
            Process a POST request and create a new user.

            Args:
                request (Request): The Django request object.

            Returns:
                JsonResponse: The response indicating the status of the operation and any errors.
            """
        # проверяем обязательные аргументы
        if {'first_name', 'last_name', 'email', 'password', 'company', 'position'}.issubset(request.data):

            # проверяем пароль на сложность
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                error_array = []
                for item in password_error:
                    error_array.append(item)
                return JsonResponse({'Status': False, 'Errors': {'password': error_array}})
            else:
                # проверяем данные для уникальности имени пользователя

                user_serializer = UserSerializer(data=request.data)
                if user_serializer.is_valid():
                    # сохраняем пользователя
                    user = user_serializer.save()
                    user.set_password(request.data['password'])
                    user.save()

                    # Создаем токен для нового пользователя
                    # token = ConfirmEmailToken.objects.create(user=user, key='3abeab8e34a5')
                    # token.save()

                    return JsonResponse({'Status': True})
                else:
                    return JsonResponse({'Status': False, 'Errors': user_serializer.errors})
                
       # Удаление пользователя методом DELETE
    def delete(self, request, user_id, *args, **kwargs):
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        user.delete()
        print(f'User {user_id} deleted')
        return Response({'detail': f'User with ID {user_id} has been successfully deleted.'}, status=status.HTTP_200_OK)
        


class ConfirmAccount(APIView):
    """
    Класс для подтверждения почтового адреса
    """

    # Регистрация методом POST
    def post(self, request, *args, **kwargs):
        """
                Подтверждает почтовый адрес пользователя.

                Args:
                - request (Request): The Django request object.

                Returns:
                - JsonResponse: The response indicating the status of the operation and any errors.
                """
        # проверяем обязательные аргументы
        if {'email', 'token'}.issubset(request.data):

            email = request.data['email']
            token_value = request.data['token']

            print(f"Received email: {email}")
            print(f"Received token: {token_value}")

            # Выводим все токены из базы данных
            print("All tokens in the database:")
            for token in ConfirmEmailToken.objects.all():
                print(f"Email: {token.user.email}, Token: {token.key}")



            print(f"Searching for token with email: {request.data['email']} and token: {request.data['token']}")
            token = ConfirmEmailToken.objects.filter(user__email=request.data['email'],
                                                     key=request.data['token']).first()
            if token:
                print(f"Found token: {token.key} for user with email: {token.user.email}")
                token.user.is_active = True
                token.user.save()
                token.delete()
                return JsonResponse({'Status': True})
            else:
                print("Token not found in the database")
                return JsonResponse({'Status': False, 'Errors': 'Неправильно указан токен или email'})


        print("Missing required arguments")
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})



class AccountDetails(APIView):
    """
    A class for managing user account details.

    Methods:
    - get: Retrieve the details of the authenticated user.
    - post: Update the account details of the authenticated user.

    Attributes:
    - None
    """

    # получить данные
    def get(self, request: Request, *args, **kwargs):
        """
               Retrieve the details of the authenticated user.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the details of the authenticated user.
        """

        print("Request headers:", request.headers)
        print("Request user:", request.user)


        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    # Редактирование методом POST
    def post(self, request, *args, **kwargs):
        """
                Update the account details of the authenticated user.

                Args:
                - request (Request): The Django request object.

                Returns:
                - JsonResponse: The response indicating the status of the operation and any errors.
                """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        # проверяем обязательные аргументы

        if 'password' in request.data:
            errors = {}
            # проверяем пароль на сложность
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                error_array = []
                # noinspection PyTypeChecker
                for item in password_error:
                    error_array.append(item)
                return JsonResponse({'Status': False, 'Errors': {'password': error_array}})
            else:
                request.user.set_password(request.data['password'])

        # проверяем остальные данные
        user_serializer = UserSerializer(request.user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
            return JsonResponse({'Status': True})
        else:
            return JsonResponse({'Status': False, 'Errors': user_serializer.errors})




# Shoowing all Users in Base
class UserListView(generics.ListAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer





class LoginAccount(APIView):
    """
    Класс для авторизации пользователей
    """

    # Авторизация методом POST
    def post(self, request, *args, **kwargs):
        if {'email', 'password'}.issubset(request.data):
            email = request.data['email']
            password = request.data['password']
            print(f"Authenticating user with email: {email} and password: {password}")

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                print("User does not exist")
                return JsonResponse({'Status': False, 'Errors': 'Пользователь с таким email не существует'})
            
            print(f"Hashed password for user '{email}' in the database: {user.password}")

            if user.check_password(password):
                print(f"Password check successful: Entered password '{password}' matches the password in the database for user '{email}'")
                if user.is_active:
                    token, _ = Token.objects.get_or_create(user=user)
                    user.token = token.key
                    print("Created token:", token.key)
                    user.save()
                    return JsonResponse({'Status': True, 'Token': token.key})
                else:
                    print("User is not active")
                    return JsonResponse({'Status': False, 'Errors': 'Пользователь не активен'})
            else:
                print(f"Password check failed: Entered password '{password}' does not match the password in the database for user '{email}'")
                return JsonResponse({'Status': False, 'Errors': 'Неправильный пароль'})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})
    


class CategoryView(ListAPIView):
    """
    Класс для просмотра категорий
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer




class ShopView(ListAPIView):
    """
    Класс для просмотра списка магазинов
    """
    queryset = Shop.objects.filter(state=True)
    serializer_class = ShopSerializer


class ProductInfoView(APIView):
    """
        A class for searching products.

        Methods:
        - get: Retrieve the product information based on the specified filters.

        Attributes:
        - None
        """

    def get(self, request: Request, *args, **kwargs):
        """
               Retrieve the product information based on the specified filters.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the product information.
               """
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop_id=shop_id)

        if category_id:
            query = query & Q(product__category_id=category_id)

        # фильтруем и отбрасываем дуликаты
        queryset = ProductInfo.objects.filter(
            query).select_related(
            'shop', 'product__category').prefetch_related(
            'product_parameters__parameter').distinct()

        serializer = ProductInfoSerializer(queryset, many=True)

        return Response(serializer.data)


class BasketView(APIView):
    """
    A class for managing the user's shopping basket.

    Methods:
    - get: Retrieve the items in the user's basket.
    - post: Add an item to the user's basket.
    - put: Update the quantity of an item in the user's basket.
    - delete: Remove an item from the user's basket.

    Attributes:
    - None
    """

    # получить корзину
    def get(self, request, *args, **kwargs):
        """
                Retrieve the items in the user's basket.

                Args:
                - request (Request): The Django request object.

                Returns:
                - Response: The response containing the items in the user's basket.
                """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        basket = Order.objects.filter(
            user_id=request.user.id, state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(basket, many=True)
        return Response(serializer.data)

    # редактировать корзину
    def post(self, request, *args, **kwargs):
        """
               Add an items to the user's basket.

               Args:
               - request (Request): The Django request object.

               Returns:
               - JsonResponse: The response indicating the status of the operation and any errors.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_sting = request.data.get('items')
        if items_sting:
            try:
                items_dict = load_json(items_sting)
            except ValueError:
                return JsonResponse({'Status': False, 'Errors': 'Неверный формат запроса'})
            else:
                basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
                objects_created = 0
                for order_item in items_dict:
                    order_item.update({'order': basket.id})
                    serializer = OrderItemSerializer(data=order_item)
                    if serializer.is_valid():
                        try:
                            serializer.save()
                        except IntegrityError as error:
                            return JsonResponse({'Status': False, 'Errors': str(error)})
                        else:
                            objects_created += 1

                    else:

                        return JsonResponse({'Status': False, 'Errors': serializer.errors})

                return JsonResponse({'Status': True, 'Создано объектов': objects_created})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    # удалить товары из корзины
    def delete(self, request, *args, **kwargs):
        """
                Remove  items from the user's basket.

                Args:
                - request (Request): The Django request object.

                Returns:
                - JsonResponse: The response indicating the status of the operation and any errors.
                """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_sting = request.data.get('items')
        if items_sting:
            items_list = items_sting.split(',')
            basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
            query = Q()
            objects_deleted = False
            for order_item_id in items_list:
                if order_item_id.isdigit():
                    query = query | Q(order_id=basket.id, id=order_item_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = OrderItem.objects.filter(query).delete()[0]
                return JsonResponse({'Status': True, 'Удалено объектов': deleted_count})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    # добавить позиции в корзину
    def put(self, request, *args, **kwargs):
        """
               Update the items in the user's basket.

               Args:
               - request (Request): The Django request object.

               Returns:
               - JsonResponse: The response indicating the status of the operation and any errors.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_sting = request.data.get('items')
        if items_sting:
            try:
                items_dict = load_json(items_sting)
            except ValueError:
                return JsonResponse({'Status': False, 'Errors': 'Неверный формат запроса'})
            else:
                basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
                objects_updated = 0
                for order_item in items_dict:
                    if type(order_item['id']) == int and type(order_item['quantity']) == int:
                        objects_updated += OrderItem.objects.filter(order_id=basket.id, id=order_item['id']).update(
                            quantity=order_item['quantity'])

                return JsonResponse({'Status': True, 'Обновлено объектов': objects_updated})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class PartnerUpdate(APIView):
    """
    A class for updating partner information.

    Methods:
    - post: Update the partner information.

    Attributes:
    - None
    """

    def post(self, request, *args, **kwargs):
        """
                Update the partner price list information.

                Args:
                - request (Request): The Django request object.

                Returns:
                - JsonResponse: The response indicating the status of the operation and any errors.
                """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        url = request.data.get('url')
        if url:
            validate_url = URLValidator()
            try:
                validate_url(url)
            except ValidationError as e:
                return JsonResponse({'Status': False, 'Error': str(e)})
            else:
                stream = get(url).content

                data = load_yaml(stream, Loader=Loader)

                shop, _ = Shop.objects.get_or_create(name=data['shop'], user_id=request.user.id)
                for category in data['categories']:
                    category_object, _ = Category.objects.get_or_create(id=category['id'], name=category['name'])
                    category_object.shops.add(shop.id)
                    category_object.save()
                ProductInfo.objects.filter(shop_id=shop.id).delete()
                for item in data['goods']:
                    product, _ = Product.objects.get_or_create(name=item['name'], category_id=item['category'])

                    product_info = ProductInfo.objects.create(product_id=product.id,
                                                              external_id=item['id'],
                                                              model=item['model'],
                                                              price=item['price'],
                                                              price_rrc=item['price_rrc'],
                                                              quantity=item['quantity'],
                                                              shop_id=shop.id)
                    for name, value in item['parameters'].items():
                        parameter_object, _ = Parameter.objects.get_or_create(name=name)
                        ProductParameter.objects.create(product_info_id=product_info.id,
                                                        parameter_id=parameter_object.id,
                                                        value=value)

                return JsonResponse({'Status': True})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class PartnerState(APIView):
    """
       A class for managing partner state.

       Methods:
       - get: Retrieve the state of the partner.

       Attributes:
       - None
       """
    # получить текущий статус
    def get(self, request, *args, **kwargs):
        """
               Retrieve the state of the partner.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the state of the partner.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        shop = request.user.shop
        serializer = ShopSerializer(shop)
        return Response(serializer.data)

    # изменить текущий статус
    def post(self, request, *args, **kwargs):
        """
               Update the state of a partner.

               Args:
               - request (Request): The Django request object.

               Returns:
               - JsonResponse: The response indicating the status of the operation and any errors.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)
        state = request.data.get('state')
        if state:
            try:
                Shop.objects.filter(user_id=request.user.id).update(state=strtobool(state))
                return JsonResponse({'Status': True})
            except ValueError as error:
                return JsonResponse({'Status': False, 'Errors': str(error)})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class PartnerOrders(APIView):
    """
    Класс для получения заказов поставщиками
     Methods:
    - get: Retrieve the orders associated with the authenticated partner.

    Attributes:
    - None
    """

    def get(self, request, *args, **kwargs):
        """
               Retrieve the orders associated with the authenticated partner.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the orders associated with the partner.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        order = Order.objects.filter(
            ordered_items__product_info__shop__user_id=request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(order, many=True)
        return Response(serializer.data)


class ContactView(APIView):
    """
       A class for managing contact information.

       Methods:
       - get: Retrieve the contact information of the authenticated user.
       - post: Create a new contact for the authenticated user.
       - put: Update the contact information of the authenticated user.
       - delete: Delete the contact of the authenticated user.

       Attributes:
       - None
       """

    # получить мои контакты
    def get(self, request, *args, **kwargs):
        """
               Retrieve the contact information of the authenticated user.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the contact information.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        contact = Contact.objects.filter(
            user_id=request.user.id)
        serializer = ContactSerializer(contact, many=True)
        return Response(serializer.data)

    # добавить новый контакт
    def post(self, request, *args, **kwargs):
        """
               Create a new contact for the authenticated user.

               Args:
               - request (Request): The Django request object.

               Returns:
               - JsonResponse: The response indicating the status of the operation and any errors.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'city', 'street', 'phone'}.issubset(request.data):
            request.data._mutable = True
            request.data.update({'user': request.user.id})
            serializer = ContactSerializer(data=request.data)

            if serializer.is_valid():
                serializer.save()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False, 'Errors': serializer.errors})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    # удалить контакт
    def delete(self, request, *args, **kwargs):
        """
               Delete the contact of the authenticated user.

               Args:
               - request (Request): The Django request object.

               Returns:
               - JsonResponse: The response indicating the status of the operation and any errors.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_sting = request.data.get('items')
        if items_sting:
            items_list = items_sting.split(',')
            query = Q()
            objects_deleted = False
            for contact_id in items_list:
                if contact_id.isdigit():
                    query = query | Q(user_id=request.user.id, id=contact_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = Contact.objects.filter(query).delete()[0]
                return JsonResponse({'Status': True, 'Удалено объектов': deleted_count})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    # редактировать контакт
    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            """
                   Update the contact information of the authenticated user.

                   Args:
                   - request (Request): The Django request object.

                   Returns:
                   - JsonResponse: The response indicating the status of the operation and any errors.
                   """
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if 'id' in request.data:
            if request.data['id'].isdigit():
                contact = Contact.objects.filter(id=request.data['id'], user_id=request.user.id).first()
                print(contact)
                if contact:
                    serializer = ContactSerializer(contact, data=request.data, partial=True)
                    if serializer.is_valid():
                        serializer.save()
                        return JsonResponse({'Status': True})
                    else:
                        return JsonResponse({'Status': False, 'Errors': serializer.errors})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class OrderView(APIView):
    """
    Класс для получения и размешения заказов пользователями
    Methods:
    - get: Retrieve the details of a specific order.
    - post: Create a new order.
    - put: Update the details of a specific order.
    - delete: Delete a specific order.

    Attributes:
    - None
    """

    # получить мои заказы
    def get(self, request, *args, **kwargs):
        """
               Retrieve the details of user orders.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the details of the order.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        order = Order.objects.filter(
            user_id=request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(order, many=True)
        return Response(serializer.data)

    # разместить заказ из корзины
    def post(self, request, *args, **kwargs):
        """
               Put an order and send a notification.

               Args:
               - request (Request): The Django request object.

               Returns:
               - JsonResponse: The response indicating the status of the operation and any errors.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'id', 'contact'}.issubset(request.data):
            if request.data['id'].isdigit():
                try:
                    is_updated = Order.objects.filter(
                        user_id=request.user.id, id=request.data['id']).update(
                        contact_id=request.data['contact'],
                        state='new')
                except IntegrityError as error:
                    print(error)
                    return JsonResponse({'Status': False, 'Errors': 'Неправильно указаны аргументы'})
                else:
                    if is_updated:
                        new_order.send(sender=self.__class__, user_id=request.user.id)
                        return JsonResponse({'Status': True})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})
