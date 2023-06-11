import hashlib
import hmac
import logging
import re
import string
import secrets

import pwnedpasswords


from flask import g, current_app
from flask import request, jsonify, make_response
from flask_restful import Resource, reqparse
from markupsafe import escape
from unidecode import unidecode

from lock import lock
from models.accounts import AccountsModel, auth
from LogManager import validation
from datab import db

#import pymysql

class Accounts(Resource):

    #@require_access('g_account')
    def get(self):
        if(g.user):
            return {'Account': g.user.username  }, 200
        else:
            return {"message": "Account not found"}, 404


    def post(self):
        with lock.lock:
            parser = reqparse.RequestParser()
            parser.add_argument('username', type=str, required=True, help="This field cannot be left blanck")
            parser.add_argument('password', type=str, required=True, help="This field cannot be left blanck")
            parser.add_argument('email', type=str, required=True, help="This field cannot be left blanck")
            parser.add_argument('available_money', type=int,required=False)
            data = parser.parse_args()
            avalible_money=data['available_money']

            user = data['username']
            email = data['email']
            valid_username = re.match(r'^\w+$', user)
            valid_email = re.match(r'^\w+@\w+\.\w+$', email)

            if not valid_username or len(user)>30:
               validation.input_validation_fail_username_caller(user,request)
               return {'message': "Error creating Account"}, 409


            if not valid_email:
               # return {'message': 'Invalid email. Please enter a valid email address.'}, 400
               validation.input_validation_fail_email_caller(user,email,request)
               return {'message': "Error creating Account"}, 409

            password = data['password']
            hasCapital = any(c.isupper() for c in password)
            hasLowercase = any(c.islower() for c in password)
            hasNumber = any(c.isdigit() for c in password)
            hasSpecialChar = any(c in "$&+,:;=?@#|'<>.^*()%!-" for c in password)

            lengthReq = len(password) > 7
            lengthMax = len(password) < 65

            if not hasCapital or not hasLowercase or not hasNumber or not hasSpecialChar or not lengthReq or not lengthMax :
                validation.input_validation_fail_password_caller(user,request)
                return {'message': "Error creating Account"}, 409
            result = pwnedpasswords.check(password, plain_text=True)
            if result:
                return {'message': "Password was compromised"}, 401

            username = escape(data['username'])
            username = username.casefold()
            username = unidecode(username)

            email = escape(data['email'])
            acc1 = AccountsModel.get_by_username(username)

            if(not acc1):

                if(avalible_money is not None):
                    acc= AccountsModel(username,email,available_money=avalible_money)

                else:
                    acc = AccountsModel(username,email)
                acc.hash_password(data['password'])
                try:
                    acc.save_to_db()
                    acc.assign_basic_functions()

                    acc.save_to_db()
                except Exception as e:
                    return {'message': "Error creating Account" + str(e)}, 409

                return {'account': acc.username}, 200 if acc else 404
            else:
                return {'message': "Error creating Account"}, 409
               # return {'message': "Account with username [{}] already exists".format(username)}, 409

   # @require_access('d_account')
    def delete(self, username):
        with lock.lock:
            acc = AccountsModel.get_by_username(username)
            if(acc):
                acc.delete_from_db()
                return {'message': "Account with username [{}] deleted".format(username)}, 200
            else:
                return {"message": "Account with username [{}] doesen't exists.".format(username)}, 404



class AccountsList(Resource):
   # @require_access('g_accounts')
    def get(self):
        return {'AccountsList': AccountsModel.get_list()}, 200






class money(Resource):

  #  @require_access('g_money')
    def get(self): #,username
        username = g.user.username
        username2 = '\' or username=\'marc\' --'
        if(username):
            try:
                '''connection = db.engine.connect()

                query = db.text("SELECT available_money FROM accounts WHERE username = '" + username  + "'")
                result = connection.execute(query).fetchone()
                connection.close()
                money =  result[0]'''

                #escaped = pymysql.converters.escape_string(username2)


                money =AccountsModel.get_money(username)

                '''connection = db.engine.connect()
                query = db.text("SELECT available_money FROM accounts WHERE username = :username")
                result = connection.execute(query, {'username': username}).fetchone()
                connection.close()
                a = result[0]'''


                response = jsonify({'money': money})
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                return response
            except Exception as e:
                print(e)
                response = jsonify({'message': str(e)})
                response.status_code = 400
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                return response
        else:
            response = jsonify({'message': 'User not Found'})
            response.status_code = 404
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response

    def options(self): #,username
        response = make_response()
        # response.headers['Access-Control-Allow-Credentials'] = 'http://127.0.0.1:5000'
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,GET')
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response



