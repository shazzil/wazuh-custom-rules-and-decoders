# Basic Firewall Rules (iptables)

#	Allows all packets from existing user 
         iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# 2)	Secure SSH Access (Port 22)
      # allows SSH access (port 22) ONLY from the specific source IP address 10.253.101.34 (white listed ip address)
          iptables -A INPUT -s 10.253.101.34/32 -p tcp -m tcp --dport 22 -j ACCEPT


      # Logs all NEW connection attempts with SYN flag to port 22 ( for finding the brute force attempt)
          
          iptables -A INPUT -p tcp -m tcp --dport 22 --tcp-flags FIN,SYN,RST,ACK SYN -j LOG --log-prefix "SSH-BLOCKED: "

      # Drops all remaining traffic destined for port 22.
       iptables -A INPUT -p tcp -m tcp --dport 22 -j DROP
 
# 3) SYN Scan/Flood Protection

      	# Marks the source IP  using (--rsource) of any packet with the SYN flag set into synscan
                                                 
          iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m recent --set --name synscan --mask 255.255.255.255 --rsource

      	# This rules log the event  with the source IP attempts 8 or more new connections with in one second
   
          iptables -A INPUT -p tcp -m tcp --dport 22 --tcp-flags FIN,SYN,RST,ACK SYN -j LOG --log-prefix "SSH-BLOCKED: "

# 4)    Single  SYN  protection ( example with FTP)  
    #Logs any attempt to FTP (a single SYN packet)
  
       iptables  -A INPUT -p tcp -m tcp --dport 21 --tcp-flags FIN,SYN,RST,ACK SYN -m state  --state  NEW -j LOG --log-prefix "FTP-SINGLE-SYN-SCAN: "
   
    # Drops all traffic to port 21 
        iptables -A INPUT -p tcp -m tcp --dport 21 -j DROP

# 5)  FIN Scan Detection
    #Logs packets where only the FIN flag is set
    
        iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN -m limit --limit 5/min -j LOG --log-prefix "NMAP_FIN_SCAN: "

    #	Drops all packets that have only the FIN flag set
    
        iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN -j DROP
