import pickle
import json

from flask_restful import Resource
from Persona import Persona as person
from models.accounts import auth, g
from flask import request
#from lxml import etree
import defusedxml.ElementTree
from LogManager import validation
class XML_HTTP(Resource):


   # @require_access('p_xml')
    def post(self):
        try:

            archivo = request.files['archivo']
            size = int(request.form.get('size'))
            if archivo:
                if(size > 1024 * 1024):
                    validation.input_validation_fail_file_size_caller(g.user.username,request)
                    return 'The file is too big. Max 1MB.',400

                nombre_archivo = archivo.filename
                if nombre_archivo.endswith('.json'):
                    # Deserializar archivo JSON
                    json_data = archivo.read()
                    persona_recuperada = json.loads(json_data)
                    if isinstance(persona_recuperada,
                                  dict) and 'nombre' in persona_recuperada and 'edad' in persona_recuperada and len(persona_recuperada) == 2:
                        #Hacer la operacion que se crea conveniente
                        return {'message': 'JSON received and processed successfully.'}, 200
                    else:
                        return {'message':'Invalid object format. Check the required attributes.'}, 400

                    '''elif nombre_archivo.endswith('.pickle'):
                    # Deserializar archivo Pickle
                    persona_recuperada = pickle.load(archivo)
                    return 'PICKLE received and processed successfully.', 200'''
                elif nombre_archivo.endswith('.xml'):

                    '''parser = etree.XMLParser(resolve_entities=False)
                    tree = etree.parse(archivo, parser)
                    tree2 = etree.parse(archivo)

                    print('--------------TREE---------------')
                    for element in tree.iter():
                        print(f"Elemento: {element.tag}")
                        print(f"Contenido: {element.text}")
                        print("---")
                    print('---------------TREE2---------------')
                    for element in tree2.iter():
                        print(f"Elemento: {element.tag}")
                        print(f"Contenido: {element.text}")
                        print("---")'''

                    tree3 = defusedxml.ElementTree.parse(archivo)
                    print('---------------TREE3---------------')
                    for element in tree3.iter():
                        print(f"Elemento: {element.tag}")
                        print(f"Contenido: {element.text}")
                        print("---")

                    return {'message': 'XML processed successfully.'}, 200

                else:
                    return {'message':'Invalid file extension'} , 400


            else:
                return {'message':'No file provided.'}, 400
        except Exception as e:
            return {'message':'Error analyzing the file'}, 500



