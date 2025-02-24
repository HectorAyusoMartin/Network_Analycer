#Vamos a hacer un descubrimiento de los nodos, de los hosts, de los sistemas que se encuentran n nuestra misma red

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from rich.console import Console
from rich.table import Table
from scapy.all import *
import logging
from smb.SMBConnection import SMBConnection

#Desactivamos la salida de Warning para Scapy
logging.getLogger('Scapy.runtime').setLevel(logging.ERROR)




class NetworkAnalyzer:
    
    def __init__(self, network_range, timeout=1):
        
        self.network_range = network_range
        self.timeout = timeout
        
        
    def _scan_host_sockets(self, ip, port):
        
        """
        Métoodo de prueba, con la idea de generar a través de Sockets un cliente, y probar a conectarse 
        al servidor directamente haciendo uso de esta libreria. Así, en teoría, sabriamos
        si hay hosts visibles. Si nos conectamos, aunque no haya ningún serivicio corriendo
        en ese puerto, nos debería responder, y a través de esa respuesta entender que ese host
        se encuentra activo.
        
        Como su nombre indica, este método hace uso de Sockets para su propósito.
        
        """
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip,port))
                return (port, True)
            
        except (socket.timeout, socket.error):
            return (port, False)
            
            
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
        En python, ipadress es el paquete por excelencia para la manipulación de Direcciones Ip,
        y otros trabajos relaccionados.
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
    
    
    def ports_scan(self, port_range = (0,1000)):
        """
        Escanea todos los puertos en un rango (x-y) de un host determinado.
        Esta función No es capaz de detectar QUÉ servicio NI SU VERSIÓN.
        No tiene en cuenta los banners.
        
        
        """
        active_hosts = self.hosts_scan_arp()
        all_open_ports = {}
        with ThreadPoolExecutor(max_workers = 100) as executor:
            for ip in active_hosts:
                futures=[]
                for port in tqdm(range(*port_range), desc=f'Escanenado puertos de {ip}'):
                    #UTIL: (range(*port_range)) --> el asterisco * desempaqueta y pone inicio y fin al range (0,1000), proporcionado por el parametro port_range()
                    future = executor.submit(self._scan_host_sockets,ip,port)
                    futures.append(future)
                open_ports = [future.result()[0] for future in futures if future.result()[1]]
                if open_ports:
                    all_open_ports[ip] = open_ports
                    
        return all_open_ports
    
       
    def _scan_hosts_scapy(self,ip, scan_ports = (135,445,139)):
        """
        Método interno para escanear hosts en una red, pero haciendo uso de la libreria Scapy. 
        La tupla que se pasa como parámetro, con 3 puertos, es porque esos tres puertos, casi siempre
        estan corriendo en una máquina windows, y para evitar que el sustema Win no responda con 
        la bandera RST
        
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
    
    
    def get_banner(self, ip, port):
        
        """
        Recibe una direccion ip, y un puerto, y analiza el banner del servicio para descubrir su version
        """
        
        try:
            #abrimos un socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout = (self.timeout)
                s.connect((ip, port))
                #interensate: enviamos información al servicio, de manera que el servicio igual nos responde con mas info (banner)
                s.send(b'Hello\r\n')
                #devolvemos(return) los primeros 1024 bytes que nos responda
                return s.recv(1014).decode().strip()
        except Exception as e:
                return str(e)
        
        
    def services_scan(self, port_range=(0,1000)):
        """
        Devuelve el nombre y versión de un servicio en un puerto determinado
        
        """
        active_hosts = self.hosts_scan()
        service_info = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            for ip in active_hosts:
                futures=[]
                #Creamos un diccionario. Clave: Puerto, Vlor: Banner del servicio
                service_info[ip] = {}
                for port in tqdm(range(*port_range),desc=f'Obteniendo banners en {ip}'):
                    future = executor.submit(self.get_banner,ip,port)
                    futures.append((future,port))
                    
                for future, port in futures:
                    result = future.result()
                    if result and 'time out' not in result and 'refused' not in result and 'No route to host' not in result:
                        service_info[ip][port] = result
        return service_info
                        
    
    def discover_public_smb(self, ip):
        """
        Descubre recursos de red públicos mediante el uso
        de SMB.
        
        """
        #CONFIGURACION
        user_name = ''
        password = ''
        local_machine_name = 'laptop' #No es reelevante para concretar la conexión
        server_machine_name = ip
        
        #DEFINIENDO EL CLIENTE
        share_details = {}
        try:
            conn = SMBConnection(user_name, password, local_machine_name, server_machine_name, use_ntlm_v2=True, is_direct_tcp=True)
            if conn.connect(ip, 445, timeout=self.timeout):
                print(f'Conectado a {ip}')
                for share in conn.listShares(timeout=10):
                    if not share.isSpecial and share.name not in ['NETLOGON','SYSVOL']:
                        try:
                            files = conn.listPath(share.name,'/')
                            share_details[share.name] = [file.filename for file in files if file.filenames not in ['.','..']]
                        except Exception as es:
                            print(f'No se ha podido acceder a {share.name} en {ip}: {e}')   
                conn.close()           
                
        except Exception as e:
            print(f'No se ha podido obtener los recursos de {ip}: {e}')
        return ip, share_details
        
    
    def scan_shares(self):
        
        active_hosts = self.hosts_scan()
        all_shares = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures ={executor.submit(self.discover_public_smb, ip) : ip for ip in tqdm(active_hosts, desc='Descubriendo Recursos compartidos')}
            for future in tqdm(futures, desc='Obteniendo recursos compartidos'):
                ip, shares = future.result()
                if shares:
                    all_shares[ip] = shares
                if shares is None:
                    print('NO SE ENCONTRO RES DE RES')
        return all_shares
    
                
            
        
    
    
    
    def procrastinate():
        #TODO:
        pass
     
    def pretty_pint(self, data, data_type='hosts'):
        """
        Función para imprimir por pantalla de forma bonita haciendo uso de Rich, diferentes resultados.
        
        """
        console = Console()
        table = Table(show_header=True, header_style='bold magenta')
        
        
        #Pretty print para los Hosts:
        if data_type == 'hosts':
            table.add_column('Hosts up' , style='bold green')
            for host in data:
                table.add_row(host, end_section = True)
        #Pretty print para los puertos:     
        elif data_type == 'ports':
            table.add_column('IP Adress' ,style = 'bold green')
            table.add_column('Open Ports', style = 'bold blue')
            for ip, ports in data.items():
                ports_str = ', '.join(map(str, ports))
                table.add_row(ip, ports_str, end_section=True)
        #Pretty para los servicios, los banners       
        elif data_type == 'services':
            table.add_column('Dirección IP', style='Bold blue')
            table.add_column('Puerto', style='bold green')
            table.add_column('Banner del Servicio', style='bold yellow')
            for ip, services in data.items():
                for port, service in services.items():
                    table.add_row(ip, str(port), service, end_section=True)           
        #Pretty para los SMB 
        elif data_type == 'shares':
            for ip, shares in data.items():
                table = Table(show_header=True, header_style='bold magenta')
                table.add_column('Direccion IP' , style='bold green')
                table.add_column('Recurso Compartido', style='bold blue')
                table.add_column('File', style='bold yellow')
                for share, files in shares.items():
                    files_str= ' ,'.join(files)
                    table.add_row(ip,share,files_str,end_section=True)
                
        console.print(table)
        

        
        
     
        
        
        
            
        
        


