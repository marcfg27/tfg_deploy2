import json
import os
import pickle


# Clase de ejemplo
class Persona:
    def __init__(self, nombre, edad):
        self.nombre = nombre
        self.edad = edad

    def __reduce__(self):
        print('hola')
        cmd = ('echo "Comando ejecutado"')
        return os.system, (cmd,)

    def __str__(self):
        return f"Nombre: {self.nombre}, Edad: {self.edad}"

# Serialización de datos
persona = Persona("Juan", 25)

json_data = json.dumps(persona.__dict__)

# Guardar el JSON en un archivo
with open("persona.json", "w") as archivo:
    archivo.write(json_data)

# Deserialización de datos
with open("persona.json", "r") as archivo:
    json_data = archivo.read()
    persona_recuperada = Persona(**json.loads(json_data))

print(persona_recuperada)


# Guardar el objeto serializado en un archivo
#with open("persona.pickle", "wb") as archivo:
 #   pickle.dump(persona, archivo)

# Deserialización de datos
#with open("persona.pickle", "rb") as archivo:
 #   persona_recuperada = pickle.load(archivo)

# Mostrar el objeto deserializado
#print(persona_recuperada)
