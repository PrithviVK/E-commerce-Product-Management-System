from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework import status
from .models import Product, Category, Review
from .serializers import ProductSerializer, CategorySerializer, ReviewSerializer
from django.shortcuts import render
# from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q, Prefetch
from django.utils import timezone
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse

from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from django.contrib.auth import views as auth_views
from django.urls import path
from django.shortcuts import redirect



# Product views

@api_view(['GET', 'POST'])
def product_list(request):
    if request.method == 'GET':
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def product_detail(request, id):
    try:
        product = Product.objects.get(pk=id)
        # product = Product.objects.get()
    except Product.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = ProductSerializer(product)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = ProductSerializer(product, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        product.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Category views

@api_view(['GET', 'POST'])
def category_list(request):
    if request.method == 'GET':
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def category_detail(request, id):
    try:
        category = Category.objects.get(pk=id)
    except Category.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = CategorySerializer(category)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = CategorySerializer(category, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        category.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
@api_view(['GET', 'POST']) 
def review_list(request, product_id):
    if request.method == 'GET':
        reviews = Review.objects.filter(product_id=product_id)
        serializer = ReviewSerializer(reviews, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        data = request.data.copy()
        data['product'] = product_id
        
        # Ensure customer_id is present
        if 'customer_id' not in data:
            return Response({"error": "customer_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = ReviewSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse({"success": True, "message": "Review added successfully"}, status=201)
            # Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# @api_view(['GET', 'POST']) (1)
# def review_list(request, product_id):
#     if request.method == 'GET':
#         reviews = Review.objects.filter(product_id=product_id)
#         serializer = ReviewSerializer(reviews, many=True)
#         return Response(serializer.data)

#     elif request.method == 'POST':
#         if not request.user.is_authenticated:
#             return Response({"error": "Authentication is required to add reviews"}, status=status.HTTP_401_UNAUTHORIZED)
        
#         data = request.data.copy()
#         data['product'] = product_id

#         # Ensure customer_id is present
#         if 'customer_id' not in data:
#             return Response({"error": "customer_id is required"}, status=status.HTTP_400_BAD_REQUEST)

#         serializer = ReviewSerializer(data=data)
#         if serializer.is_valid():
#             serializer.save()
#             return JsonResponse({"success": True, "message": "Review added successfully"}, status=201)
        
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# views.py

from rest_framework.permissions import AllowAny

# @api_view(['GET'])
# @permission_classes([AllowAny])
# def review_list(request, product_id):
#     if request.user.is_authenticated:
#         return Response({"error": "Authenticated users cannot view reviews"}, status=status.HTTP_403_FORBIDDEN)
#     reviews = Review.objects.filter(product_id=product_id)
#     serializer = ReviewSerializer(reviews, many=True)
#     return Response(serializer.data)

# @api_view(['POST'])
# @authentication_classes([SessionAuthentication, TokenAuthentication])
# @permission_classes([IsAuthenticated])
# def review_list_post(request, product_id):
#     data = request.data.copy()
#     data['product'] = product_id
#     if 'customer_id' not in data:
#         return Response({"error": "customer_id is required"}, status=status.HTTP_400_BAD_REQUEST)
#     serializer = ReviewSerializer(data=data)
#     if serializer.is_valid():
#         serializer.save()
#         return Response({"success": "Review added successfully"}, status=status.HTTP_201_CREATED)
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def user_products_view(request):
    query = request.GET.get('q')
    if query:
        products = Product.objects.filter(
            Q(name__icontains=query) | Q(category__icontains=query)
        ).prefetch_related(Prefetch('reviews', queryset=Review.objects.all()))
    else:
        products = Product.objects.all().prefetch_related(Prefetch('reviews', queryset=Review.objects.all()))
    
    paginator = Paginator(products, 2)  # Show 2 products per page
    page_number = request.GET.get('page')
    
    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)

    context = {
        'page_obj': page_obj,
        'query': query
    }
    return render(request, 'user_products.html', context)


# @csrf_exempt
def home(request):
    all_items=Product.objects.all()#we pull all the data from our database into the all_items variable 
    return render(request,'home.html',{'all':all_items})#{} is a context dictionary to render all retrieved DB objects on the screen and reference it on the page as 'all'



#authentication purposes only 

from .serializers import UserSerializer

# @api_view(['POST']) 
# def signup(request):
#     serializer = UserSerializer(data=request.data)
#     if serializer.is_valid():
#         serializer.save()
#         user = User.objects.get(username=request.data['username'])
#         user.set_password(request.data['password'])
#         user.save()
#         token = Token.objects.create(user=user)
#         return Response({'token': token.key, 'user': serializer.data})
#     return Response(serializer.errors, status=status.HTTP_200_OK)

####
from django.contrib.auth.forms import UserCreationForm

# @api_view(['GET', 'POST']) (1)
# def signup(request):
#     if request.method == 'POST':
#         serializer = UserSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             user = User.objects.get(username=request.data['username'])
#             user.set_password(request.data['password'])
#             user.save()
#             token = Token.objects.create(user=user)
#             return Response({'token': token.key, 'user': serializer.data})
#         return Response(serializer.errors, status=status.HTTP_200_OK)
#     else:
#         form = UserCreationForm()
#         return render(request, 'register.html', {'form': form})
    
#####

###################
# @api_view(['GET', 'POST']) (3)
# def signup(request):
#     if request.method == 'POST':
#         serializer = UserSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.save()
#             token = Token.objects.create(user=user)
#             return Response({'token': token.key, 'user': serializer.data})
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#     else:
#         form = UserCreationForm()
#         return render(request, 'register.html', {'form': form})
    
###################
# @api_view(['GET', 'POST'])
# def signup(request):
#     if request.method == 'POST':
#         data = {
#             'username': request.data.get('username'),
#             'password': request.data.get('password'),
#             'email': request.data.get('email')
#         }
#         serializer = UserSerializer(data=data)
#         if serializer.is_valid():
#             user = serializer.save()
#             token = Token.objects.create(user=user)
#             return Response({'token': token.key, 'user': serializer.data})
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#     else:
#         form = UserCreationForm()
#         return render(request, 'register.html', {'form': form})

# @api_view(['POST']) (1)
# def login(request):
#     user = get_object_or_404(User, username=request.data['username'])
#     if not user.check_password(request.data['password']):
#         return Response("missing user", status=status.HTTP_404_NOT_FOUND)
#     token, created = Token.objects.get_or_create(user=user)
#     serializer = UserSerializer(user)
#     return Response({'token': token.key, 'user': serializer.data})

from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required


@api_view(['GET', 'POST'])
def signup(request):
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.set_password(request.data['password'])
            user.save()
            token = Token.objects.create(user=user)
            return Response({'token': token.key, 'user': serializer.data})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        form = UserCreationForm()
        return render(request, 'register.html', {'form': form})

# @api_view(['POST'])
# def login_view(request):
#     user = authenticate(username=request.data['username'], password=request.data['password'])
#     if user is not None:
#         login(request, user)
#         return redirect('user_dashboard')
#     return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'POST'])
def login_view(request):
    if request.method == 'POST':
        user = authenticate(username=request.data['username'], password=request.data['password'])
        if user is not None:
            login(request, user)
            return redirect('user_dashboard')
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
    return render(request, 'login.html')

@login_required
def user_dashboard(request):
    return render(request, 'user_products.html')


# Redirect to user_products after login
def login_redirect(request):
    return redirect('user_dashboard')


@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("passed!")

# Redirect to user_products after login
# def login_redirect(request):
#     return redirect('user_products')