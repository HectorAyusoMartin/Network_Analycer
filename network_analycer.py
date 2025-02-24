#Vamos a hacer un descubrimiento de los nodos, de los hosts, de los sistemas que se encuentran n nuestra misma red

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from rich.console import Console
from rich.table import Table
from scapy.all import *
import logging

#Desactivamos la salida de Warning para Scapy
logging.getLogger('Scapy.runtime').setLevel(logging.ERROR)




class NetworkAnalyzer:
    
    def __init__(self, network_range, timeout=1):
        
        self.network_range = network_range
        self.timeout = timeout
        
        
    def _scan_host_sockets(self, ip, port):
        
        """
        Métoodo de prueba, con la idea de generar a través de Sockets un cliente, y probar a conectarse al servidor directamente haciendo uso de esta libreria. Así, en teoría, sabriamos
        si hay hosts visibles. Si nos conectamos, aunque no haya ningún serivicio corriendo en ese puerto, nos debería responder, y a través de esa respuesta entender que ese host
        se encuentra activo.
        
        Como su nombre indica, este método hace uso de Sockets para su propósito.
        
        """
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip,port))
                return (ip, True)
            
        except (socket.timeout, socket.error):
            return (ip, False)
            
    def  hosts_scan_arp(self):
        """
        Descubre Hosts a través de la ténica ARP-SCAN.
        Es poco invaisvo.
        
        """    
        hosts_up = []
        network = ipaddress.ip_network(self.network_range, strict=False)
        #utilizamos scapy para componer un paquete ARP para enviar a todas las IP dentro del rango proporcionado, para ver si nos responde diciendo que tiene la dirección MAC asociada.
        arp_request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=str(network))
        response, _ = tqdm(srp(arp_request, timeout=self.timeout, iface_hint=str(network[1]), verbose=0), desc='Escaneando con ARP')
        for _ , received in response:
            hosts_up.append(received.psrc)
        return hosts_up
         
        
        
    
    
    def hosts_scan(self, scan_ports=(135,445,139)):
        """
        En python, ipadress es el paquete por excelencia para la manipulación de Direcciones Ip, y otros trabajos relaccionados.
        La función escanea todos los hosts que estan UP en un rango determinado de red.
        
        
        """
        
        network = ipaddress.ip_network(self.network_range, strict = False)
        hosts_up = []
        
        #A partir de aquí, si no aplicamos programacikón multihilo, el proceso de escaneo sería demasiado lento.
        with ThreadPoolExecutor(max_workers=100) as executor:
            
       #Añadir por aqui una barra de carga, para saber si el programa se ha trabado o sigue en ejecución, es una buena idea, debido a que dependiendo del rango de ip, el programa
       #podría tardar un poquito en terminar de hacer todo el escaneo. Con la barra obtendremos un pequeño feedback de rendimiento. (tqdm)
       #Esta linea es un buén ejemplo de uso de diccionario por compresión, donde 
            futures = {executor.submit(self._scan_hosts_scapy, str(host), scan_ports): host for host in tqdm(network.hosts(), desc='Escaneando hosts')}
            
            for future in tqdm(futures, desc='Obteniendo resultados'):
                if future.result()[1]:
                    hosts_up.append(future.result()[0])
                
        return hosts_up
       
       
    def _scan_hosts_scapy(self,ip, scan_ports = (135,445,139)):
        """
        Método interno para escanear hosts en una red, pero haciendo uso de la libreria Scapy. La tupla que se pasa como parámetro, con 3 puertos, es porque esos tres puertos, casi siempre
        estan corriendo en una máquina windows, y para evitar que el sustema Win no responda con la bandera RST
        
        """
        
        for port in scan_ports:
            #Construyendo el paquete de red que vamos a enviar
            packet = IP(dst=ip)/TCP(dport=port, flags='S', window=0x4001, options=[('MSS', 1460 )])
            #Enviandolo con scapy, y que nos va a devolver tanto la respuesta(response), y otro valor, los apquetes sin respuesta
            response,  _ =sr(packet, timeout=self.timeout, verbose = 0 )
            #Nos ha respondido?
            if response is True:
                return (ip, True)
        return (ip, False)
    
        
     
    def pretty_pint(self, data, data_type='hosts'):
        """
        Función para imprimir por pantalla de forma bonita haciendo uso de Rich, diferentes resultados.
        
        """
        console = Console()
        table = Table(show_header=True, header_style='bold magenta')
        
        if data_type == 'hosts' :
            table.add_column('Hosts up' , style='bold green')
            for host in data:
                table.add_row(host, end_section = True)
                
        console.print(table)
        

        
        
     
        
        
        
            
        
        


