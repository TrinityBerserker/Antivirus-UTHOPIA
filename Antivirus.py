import os
import hashlib
import shutil
import datetime

# Configuración de la carpeta de cuarentena
CARPETA_CUARENTENA = "./cuarentena"
LOG_FILE = "antivirus_log.txt"

# Función para registrar eventos en un archivo de log
def registrar_log(mensaje):
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.datetime.now()} - {mensaje}\n")

# Función para cargar firmas desde un archivo
def cargar_firmas(filename):
    try:
        with open(filename, 'r') as file:
            signatures = {line.strip().lower() for line in file.readlines() if line.strip()}
        return signatures
    except IOError:
        print(f"No se pudo abrir el archivo {filename}.")
        return set()

# Función para calcular hashes de un archivo
def calcular_hashes(filename):
    try:
        hashes = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}
        with open(filename, 'rb') as file:
            while chunk := file.read(65536):  # Leer en bloques de 64KB
                for h in hashes.values():
                    h.update(chunk)
        return {name: h.hexdigest().lower() for name, h in hashes.items()}
    except IOError:
        return None

# Función para mover archivo a cuarentena
def mover_a_cuarentena(filepath):
    if not os.path.exists(CARPETA_CUARENTENA):
        os.makedirs(CARPETA_CUARENTENA)
    filename = os.path.basename(filepath)
    nueva_ruta = os.path.join(CARPETA_CUARENTENA, filename)
    shutil.move(filepath, nueva_ruta)
    registrar_log(f"Archivo {filepath} movido a cuarentena.")
    print(f"Archivo {filepath} movido a cuarentena.")

# Función para analizar un archivo
def analizar_archivo(filename, firmas):
    hashes = calcular_hashes(filename)
    if not hashes:
        print(f"No se pudo calcular los hashes de {filename}.")
        return False
    
    for nombre, valor in hashes.items():
        if valor in firmas:
            print(f"Archivo {filename} identificado como malicioso ({nombre}: {valor}).")
            registrar_log(f"Detección: {filename} ({nombre}: {valor}).")
            mover_a_cuarentena(filename)
            return True
    
    print(f"Archivo {filename} limpio.")
    registrar_log(f"Archivo {filename} analizado y limpio.")
    return False

# Función para escanear una carpeta completa
def escanear_carpeta(carpeta, firmas):
    for root, _, files in os.walk(carpeta):
        for file in files:
            filepath = os.path.join(root, file)
            analizar_archivo(filepath, firmas)

# Función principal del antivirus
def main():
    signatures_file = input("Ingrese la ruta del archivo de firmas: ")
    firmas = cargar_firmas(signatures_file)
    
    if not firmas:
        print("No se encontraron firmas válidas. El antivirus no puede funcionar correctamente.")
        return
    
    opcion = input("¿Desea analizar un archivo (1) o una carpeta (2)? ")
    
    if opcion == "1":
        file_path = input("Ingrese la ruta del archivo a analizar: ")
        if os.path.isfile(file_path):
            analizar_archivo(file_path, firmas)
        else:
            print("El archivo especificado no existe.")
    elif opcion == "2":
        folder_path = input("Ingrese la ruta de la carpeta a analizar: ")
        if os.path.isdir(folder_path):
            escanear_carpeta(folder_path, firmas)
        else:
            print("La carpeta especificada no existe.")
    else:
        print("Opción no válida.")

# Ejecutar el programa principal
if __name__ == "__main__":
    main()
