import sys
import socket
import os
import time
import subprocess
import re
import argparse
import ipaddress
import threading
from queue import Queue
import ping3
from reportlab.pdfgen import canvas
from openpyxl import Workbook

# Variables globales para almacenar los resultados
scan_results = []
scan_lock = threading.Lock()

# Recibe como parámetro la IP y verifica si es válida
def check_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Revisa puertos abiertos en la IP
def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((ip, port))
    if result == 0:
        return True
    else:
        return False

# Ping para recibir el TTL
def check_ttl(ip):
    ttl = 0
    try:
        ttl = ping3.ping(ip, timeout=1, unit='ms')
        if ttl is not None:
            ttl = int(ttl)
    except PermissionError:
        print("El script requiere privilegios administrativos para ejecutarse.")
        sys.exit(1)
    except (ValueError, TypeError):
        pass
    return ttl

# Según el TTL se determina el sistema operativo
def check_os(ttl):
    os = ""
    if ttl is not None and isinstance(ttl, int):
        if ttl >= 0 and ttl <= 64:
            os = "Linux"
        elif ttl >= 65 and ttl <= 128:
            os = "Windows"
        elif ttl >= 129 and ttl <= 254:
            os = "Solaris/AIX"
    return os

# Da los puertos abiertos y cerrados de la IP
def check_host(ip, scan_ports=True):
    if check_ip(ip):
        ttl = check_ttl(ip)
        os = check_os(ttl)
        result = "IP: {} - TTL: {} - OS: {}".format(ip, ttl, os)
        scan_lock.acquire()
        scan_results.append(result)
        scan_lock.release()
        print(result)

        if scan_ports:
            for port in range(1, 10):
                if check_port(ip, port):
                    result = "Puerto {}: ABIERTO".format(port)
                else:
                    result = "Puerto {}: CERRADO".format(port)
                scan_lock.acquire()
                scan_results.append(result)
                scan_lock.release()
                print(result)

        # Generar nombres de archivo personalizados
        timestamp = time.strftime("%Y%m%d%H%M%S")
        pdf_filename = "scan_results_ip_{}_{}.pdf".format(ip, timestamp)
        excel_filename = "scan_results_ip_{}_{}.xlsx".format(ip, timestamp)

        # Guardar los resultados del escaneo en PDF y Excel con nombres personalizados
        save_scan_results(scan_results, ip, pdf_filename, excel_filename)

        return
    else:
        print("IP inválida. Ingresa una IP válida...")


# Revisa si el rango de IPs es válido y busca hosts activos e inactivos
def check_range(start_ip, end_ip):
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)

    if start > end:
        print("El rango de IPs no es válido. La IP inicial debe ser menor que la IP final.")
        return

    print("Escaneando hosts en el rango {} - {}:".format(start_ip, end_ip))


    hosts_up = []
    hosts_down = []

    for ip in range(int(start), int(end) + 1):
        ip_str = str(ipaddress.IPv4Address(ip))
        if check_ping(ip_str):
            hosts_up.append(ip_str)
            result = "IP: {} está activa.".format(ip_str)
            scan_lock.acquire()
            scan_results.append(result)
            scan_lock.release()
            print(result)
        else:
            hosts_down.append(ip_str)
            result = "IP: {} está inactiva.".format(ip_str)
            scan_lock.acquire()
            scan_results.append(result)
            scan_lock.release()
            print(result)

    print("Escaneo completo.")

    if hosts_up:
        print("\nHosts activos en el rango {} - {}:".format(start_ip, end_ip))
        for host in hosts_up:
            print(host)

    if hosts_down:
        print("\nHosts inactivos en el rango {} - {}:".format(start_ip, end_ip))
        for host in hosts_down:
            print(host)

    # Generar nombres de archivo personalizados
    timestamp = time.strftime("%Y%m%d%H%M%S")
    pdf_filename = "scan_results_range_{}_{}.pdf".format(start_ip, end_ip, timestamp)
    excel_filename = "scan_results_range_{}_{}.xlsx".format(start_ip, end_ip, timestamp)

    # Guardar los resultados del escaneo en PDF y Excel con nombres personalizados
    save_scan_results(scan_results, start_ip, pdf_filename, excel_filename)


# Comprueba si se puede hacer ping a la IP
def check_ping(ip):
    try:
        response = ping3.ping(ip, timeout=1, unit='ms')
        return response is not None
    except PermissionError:
        print("El script requiere privilegios administrativos para ejecutarse.")
        sys.exit(1)
    except (ValueError, TypeError):
        return False

# Función para guardar los resultados del escaneo en archivos PDF y Excel
def save_scan_results(results, ip, pdf_filename, excel_filename):
    # Guardar como PDF
    pdf = canvas.Canvas(pdf_filename)
    pdf.setTitle("Scan Results")

    y = 700
    for result in results:
        pdf.drawString(50, y, result)
        y -= 15

    pdf.save()
    print("Los resultados del escaneo se han guardado en el archivo PDF: {}".format(pdf_filename))

    # Guardar como Excel
    wb = Workbook()
    ws = wb.active

    for i, result in enumerate(results):
        ws.cell(row=i+1, column=1, value=result)

    wb.save(excel_filename)
    print("Los resultados del escaneo se han guardado en el archivo Excel: {}".format(excel_filename))


# Función principal
def main():
    parser = argparse.ArgumentParser(prog='pili_allports.py',
                                     description='// SCRIPT HECHO POR: DEIMIAN ROJAS //',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=False)
    parser.add_argument("-h", "--help", action="store_true", help="Mostrar este mensaje de ayuda y salir")
    parser.add_argument("-s", "--start-ip", help='IP inicial del rango a verificar')
    parser.add_argument("-e", "--end-ip", help='IP final del rango a verificar')
    parser.add_argument("-i", "--ip", help='IP para obtener información de puertos, TTL y OS')

    args = parser.parse_args()

    if args.help:
        print('\n')
        print("*************************************\n")
        print("// SCRIPT HECHO POR: DEIMIAN ROJAS //\n")
        print("*************************************\n")
        print('\n')
        print("           |INSTRUCCIONES|\n")
        print("-Ejemplos de uso: \n")
        print("[*] python3 pili_allports.py -s 64.233.186.1 -e 64.233.186.50\n")
        print("[*] python3 pili_allports.py -i 64.233.186.5\n")
        print('\n')
        print("-Opciones: \n")
        print("pili_allports.py [-h] (para mostrar instrucciones)")
        print("pili_allports.py [-s IP_inicial] [-e IP_final] (escanea un RANGO DE IP)")
        print("pili_allports.py [-i IP] (escaneo puertos de una IP)")
        print('\n')
        return

    if args.ip:
        check_host(args.ip)
    elif args.start_ip and args.end_ip:
        check_range(args.start_ip, args.end_ip)
    else:
        print('\n')
        print("*************************************\n")
        print("// SCRIPT HECHO POR: DEIMIAN ROJAS //\n")
        print("*************************************\n")
        print('\n')
        print("           |INSTRUCCIONES|\n")
        print("-Ejemplos de uso: \n")
        print("[*] python3 pili_allports.py -s 64.233.186.1 -e 64.233.186.50\n")
        print("[*] python3 pili_allports.py -i 64.233.186.5\n")
        print('\n')
        print("-Opciones: \n")
        print("pili_allports.py [-h] (para mostrar instrucciones)")
        print("pili_allports.py [-s IP_inicial] [-e IP_final] (escanea un RANGO DE IP)")
        print("pili_allports.py [-i IP] (escaneo puertos de una IP)")
        print('\n')
        return

if __name__ == "__main__":
    main()

