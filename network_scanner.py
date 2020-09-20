#!/usr/bin/env python
import scapy.all as scapy 
import optparse 

print(" ")
print("		[=------------------------------------------------------------=]                  ")
print("		[=----------------------=[  NetScanner ]=---------------------=]                  ")
print("		[=------------------=[ Coded by Eslam Akl ]=------------------=]                  ")
print("		[=----------------------=[  @eslam3kl  ]=---------------------=]                  ")
print("		[=------------------------------------------------------------=]                  ")
print(" ")

#Function to get the user input 
def get_ip(): 
	parser = optparse.OptionParser()
	parser.add_option("-i","--ip",dest="ip",help="Your IP address")
	(options, arguments) = parser.parse_args()
	#check of the user input 
	if not options.ip: 
		print("[-] Enter your IP address, see --help for more info")
		raise SystemExit 
	else: 
		return options.ip

#scan ip's of the function 
def scan(ip): 
	arp_request = scapy.ARP(pdst=ip)
	broadcast_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_broadcast_request = broadcast_request / arp_request 
	answered, unanswered = scapy.srp(arp_broadcast_request, timeout=1, verbose=False)
	client_list = [] 
	print("+-----------------------+--------------------+\n| IP \t\t\t| MAC Address\t"+"     "+"|\n+-----------------------+--------------------+")
	for element in answered: 
		client_dic = {"IP":element[1].psrc, "MAC":element[1].hwsrc}
		print("| "+element[1].psrc + "\t\t" + "| "+element[1].hwsrc+"  |")
		client_list.append(client_dic)
 	print("+-----------------------+--------------------+")


#execute 
ip_address = get_ip()
scan(ip_address)

