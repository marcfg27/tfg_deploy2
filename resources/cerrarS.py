import pickle
import json

from flask_restful import Resource
from Persona import Persona as person
from models.accounts import auth, g
from flask import request
# from lxml import etree
import defusedxml.ElementTree
from LogManager import validation


class closes(Resource):

    # @require_access('p_xml')
    def get(self):
        return {'message': 'Session closed'}, 200
