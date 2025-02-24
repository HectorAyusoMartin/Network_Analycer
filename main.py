from network_analycer import NetworkAnalyzer

if __name__ == '__main__':
    
    analyzer = NetworkAnalyzer('192.168.1.1/24')
    hosts_up  = analyzer.hosts_scan_arp()
    analyzer.pretty_pint(hosts_up)
    
    
    
    
    