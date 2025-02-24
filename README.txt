Proyecto Scripting aplicada a la Ciberseguridad con Python. Análisis y escaneo de red.

Conceptos aplicados a la programación de los scripts:


    -Scripting Cybersecurity
    -Programación multihilo.
    -Listas recursivas.
    -Diccionario por compresión
    -Poo 

    



        _scan_host_scapy():

Función de escaneo usando la técnica TCP SYNC Ping, permite identificar si un host esta avtivo 
medainte el analisis de la respuesta que nos da cuando tratamos de conectarnos a un puerto determinado.
Si hay un servicio, podremos establecer la conexión, y si no lo hay nos devolverá otro paquete TCP con 
un flag RST.
Interesante es que , el comportamiento de: tengo el puerto cerrado y no tengo ningún serivicio ejecutandose 
para ese puerto, y te devuelvo un RESET, solo se lleva a caso en  sistemasbLinux. En un sistema Windows, 
a través de este método, ni si quiera te manda la flag RESET, y por lo tanto NO se identifica la máquina windows.
Una idea para remediar esto es buscar simepre ciertos puertos, que suelen estar siempre activos, para que 
en el caso de que sea una máquina Windows, también salga en el escaner sin que se quede oculta al no responder 
con el TCP RST.
La idea práctica de este script es descubir los hosts, pero generando el mínimo tráfico de red posible.

=================================================================================================================================================================================================


        _scan_host_sockets():

Función de misma utilidad que la anterior, pero haciendolo con la librería Sockets en vez de Scapy. Mucho mas 
inproductivo haciendolo así.
También utilizamos la técnica TCP/SYNC ping para el descubrimiento de Hosts.



=================================================================================================================================================================================================

        host_scan_arp():

Esta tambien nos permite identificar hosts, pero SIN ACTUAR Directamente con ellos, sin establecer ningún tipo 
de conexión. La técnica se llama ARP-SCAN.
Es una técnica mucho menos invasiva. 

=================================================================================================================================================================================================


        ports_scan():

Escanea todos los puertos dados en una (tupla), que representa el rango.
El Objetivo del escaner sera un host determinado, recorrera con un range todos los puertos, y devolvera que 
puertos del host estan abieertos y cuales no.
En este método, se usa ténicas de programación multihilo (futures), para agilizar todo el proceso.


=================================================================================================================================================================================================

        services_scan():

Esta función implementa la lectura del banner del servicio para poder descubrir que version de usa.
La función devuelve un {Diccionario} con el numero de puerto, y el banner que obtiene del intento de 
conexión con el.

=================================================================================================================================================================================================

















