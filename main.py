from network_analycer import NetworkAnalyzer

if __name__ == '__main__':
    
    analyzer = NetworkAnalyzer('192.168.1.0/24')
    
    #Pruebas reconocimiento de Hosts en la red:
    
    hosts_up  = analyzer.hosts_scan_arp()
    analyzer.pretty_pint(hosts_up)
    
    #=========================================
    
    #Pruebas reconocimiento de puertos de un Host
    
    ports_up = analyzer.ports_scan()
    analyzer.pretty_pint(ports_up, data_type='ports')
    
    #=========================================
    
    #Reconociendo Banners
    
        #services = analyzer.services_scan()
        #analyzer.pretty_pint(services, data_type='services')
    
    #=========================================
    
    #Reconociendo recursos compartidos SMB:
    
    shares = analyzer.scan_shares()
    analyzer.pretty_pint(shares,data_type='shares')
    
    
    
    
   
    
    
    
    