import validators


import requests
from flask_restful import Resource, reqparse
from flask import request

def es_url_permitida(url):

    lista_blanca = [
        "https://127.0.0.1:5000/stock",
        "url2",
        "url3"
    ]
    return url in lista_blanca

class Product(Resource):


   # @require_access('p_xml')
   def post(self):
       try:
           parser = reqparse.RequestParser()

           parser.add_argument('stockApi', type=str, required=False)

           data = parser.parse_args()

           url = 'https://127.0.0.1:5000/stock'#data['stockApi']
           if es_url_permitida(url):
               cookies = request.cookies
               csrf_token = request.headers.get('X-CSRFToken')
               auth_token = request.headers.get('Authorization')
               headers = {
                   'X-CSRF-Token': csrf_token,
                   'Authorization': auth_token
               }
               inventory_response = requests.get(url, headers=headers, cookies=cookies, verify=False)
               inventory_data = inventory_response.json()

               return {'inventory_data': inventory_data}, 200

           else:
               return 'URL no permitida', 403
       except Exception as e:
           return {'message':'Error'}, 500


class Stock(Resource):
   # @require_access('p_xml')
    def get(self):
        return 10
