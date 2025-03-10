# Importar librerías necesarias
import os
import hashlib

# Función para cargar firmas desde un archivo
def cargar_firmas(filename):
    try:
        with open(filename, 'r') as file:
            signatures = [line.strip() for line in file.readlines() if line.strip()]
        return signatures
    except IOError:
        print(f"No se pudo abrir el archivo {filename}.")
        return []

# Función para calcular el hash MD5 de un archivo
def calcular_md5(filename):
    try:
        with open(filename, 'rb') as file:
            md5 = hashlib.md5()
            while True:
                data = file.read(65536)  # Leer en bloques de 64KB
                if not data:
                    break
                md5.update(data)
            return md5.hexdigest()
    except IOError:
        return None

# Función para analizar un archivo en busca de firmas
def analizar_archivo(filename, firmas):
    md5 = calcular_md5(filename)
    if md5 is None:
        print(f"No se pudo calcular el MD5 de {filename}.")
        return False
    
    md5_hash = md5.lower()  # Convertir a minúsculas para comparar con las firmas
    if md5_hash in firmas:
        print(f"Archivo {filename} identificado como malicioso por la firma: {md5_hash}")
        return True
    else:
        print(f"Archivo {filename} no coincide con ninguna firma conocida.")
        return False

# Función principal del antivirus
def main():
    # Pedir la ruta del archivo de firmas
    signatures_file = input("Ingrese la ruta del archivo de firmas: ")
    firmas = cargar_firmas(signatures_file)
    
    if not firmas:
        print("No se encontraron firmas válidas. El antivirus no puede funcionar correctamente.")
        return
    
    # Pedir la ruta del archivo a analizar
    file_path = input("Ingrese la ruta del archivo a analizar: ")
    
    if not os.path.isfile(file_path):
        print("El archivo especificado no existe.")
        return
    
    # Analizar el archivo proporcionado
    analizar_archivo(file_path, firmas)

# Ejecutar el programa principal
if __name__ == "__main__":
    main()
