from django.db import models
from django.utils import timezone
from django.db import models

class Category(models.Model):
    name = models.TextField(max_length=200)
    description = models.TextField(max_length=200)

    def __str__(self):
        return f"{self.name} - {self.description}"


class Product(models.Model):
    name = models.CharField(max_length=200)
    category=models.TextField(max_length=200)
    description = models.TextField(max_length=200)

    def __str__(self):
        return f"{self.name} - {self.category}"
    
class Review(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='reviews')
    rating = models.IntegerField()
    customer_id = models.IntegerField()
    comment = models.TextField(default='')

    def __str__(self):
        return f"Review {self.id} for {self.product.name}"




