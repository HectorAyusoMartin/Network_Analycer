#Vamos a hacer un descubrimiento de los nodos, de los hosts, de los sistemas que se encuentran n nuestra misma red

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from rich.console import Console
from rich.table import Table


class NetworkAnalyzer:
    
    def __init__(self, network_range, timeout=1):
        
        self.network_range = network_range
        self.timeout = timeout
        
        
    def _scan_host_sockets(self, ip, port):
        
        """
        Métoodo de prueba, con la idea de generar a través de Sockets un cliente, y probar a conectarse al servidor directamente haciendo uso de esta libreria. Así, en teoría, sabriamos
        si hay hosts visibles. Si nos conectamos, aunque no haya ningún serivicio corriendo en ese puerto, nos debería responder, y a través de esa respuesta entender que ese host
        se encuentra activo.
        
        """
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip,port))
                return (ip, True)
            
        except (socket.timeout, socket.error):
            return (ip, False)
            
            
    def hosts_scan(self, port=1000):
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
            futures = {executor.submit(self._scan_host_sockets, str(host),port): host for host in tqdm(network.hosts(), desc='Escaneando hosts')}
            
            for future in tqdm(futures, desc='Obteniendo resultados'):
                if future.result()[1]:
                    hosts_up.append(future.result()[0])
                
        return hosts_up
       
    
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
        

        
        
     
        
        
        
            
        
        


