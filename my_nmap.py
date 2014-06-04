
#coding: utf8
#######################################################################
##Instituto Tecnológico de Costa Rica								##
##Administración de Tecnologías de la Información					##
##Ataque y Protección de Sistemas Informáticas						##
##Tarea #4 de Puertos												##
##Leandro Ulloa Porras / 201001626									##
##																	##
##Resumen de funcionamiento											##
##TCP_Connect() - Completo y funcionando							##
##TCP_SYN() 	- Completo y funcionando							##
##TCP_ACK() 	- Completo y funcionando							##
##TCP_FYN() 	- Completo y funcionando							##
##TCP_UDP()		- Completo y sin probar								##
##TCP_IDDLE()	- Incompleto										##
##																	##
##Argumentos Escaneo  : ./ my_nmap <scaner> <tarjet>				##
##Argumentos Escaneo IddleScan  : ./ my_nmap -sI <zombi><dst><port> ##
##																	##
#######################################################################
import logging
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#Variables locales necesarias para el scaneo
dst_ip = sys.argv[2] 				#IP destino 
scanner = sys.argv[1] 				#tipo de escaneo a realizar
src_port = RandShort() 				#Random de ip origen
dst_port =14999 						#Destino puerto
port_closed = 0						#contador de puertos cerrados
port_unfil = 0						#contador de puertos no filtrados
port_open =0						#contador de puertos abiertos
port_fil=0							#contador de puertos filtrados
ip=IP(dst=dst_ip)					#creación del paquete ip
tcp=TCP(sport=src_port,flags="S")	#creación del paquete tcp deafault
port_zombi=0						#almacen del puerto zombi abierto 		

if (scanner== "-sT"):
	print "\n"+"TCP_Connect ()	"+ "	IP: "+dst_ip +"\n"
	while (dst_port<=15000):
		tcp_connect_resp = sr1(ip/TCP(dport=dst_port),timeout=0.5, 
		verbose=0)
		if(str(type(tcp_connect_resp))=="<type 'NoneType'>"):
			#si no hay respuesta es filtrado
			port_fil=port_fil+1
		elif(tcp_connect_resp.haslayer(TCP)):
			if(tcp_connect_resp.getlayer(TCP).flags == 0x12):
				#si la bandera A es activa envia la bandera AR
				send_rst = sr(ip/TCP(dport=dst_port, flags="AR"),
				timeout=0.5, verbose=0)
				print 'Port:' +str(dst_port).center(20)  + "\t"+ 'Open'
			elif (tcp_connect_resp.getlayer(TCP).flags == 0x14):
				#si activa la bandera R, el puerto está cerrado
				port_closed=port_closed+1
		dst_port = dst_port+1
	print "There are  " +  str(port_closed) + "  ports closed " 
	print "There are  " +  str(port_fil) + "  Filtered Ports" +"\n" 
	print  "Finish Scanning..."+"\n"		

if (scanner== "-sS"):
	print "\n"+"TCP_SYN ()	"+ "	IP: "+dst_ip +"\n"
	while (dst_port<=1000):
		tcp_syn_resp = sr1(ip/TCP(dport=dst_port),timeout=0.5, 
		verbose=0)
		if(str(type(tcp_syn_resp))=="<type 'NoneType'>"):
			#Si no recibe ningún paquete este es filtrado
			port_fil=port_fil+1
		elif(tcp_syn_resp.haslayer(TCP)):
			if(tcp_syn_resp.getlayer(TCP).flags == 0x12):
				#si activa la bandera A recibe envia la bandera R
				send_rst = sr(ip/TCP(dport=dst_port, flags="R"),
				timeout=0.5, verbose=0)
				print 'Port:' +str(dst_port).center(20)  + "\t"+ 'Open'
			elif (tcp_syn_resp.getlayer(TCP).flags == 0x14):
				#si activa la bandera R, el puerto está cerrado
				port_closed=port_closed+1
		dst_port = dst_port+1
	print "There are  " +  str(port_closed) + "  Closed Ports " 
	print "There are  " +  str(port_fil) + "  Filtered Ports" +"\n" 
	print "Finish Scanning..."+"\n"
		
if (scanner== "-sA"):
	print "\n"+"TCP_ACK	 ()	"+ "	IP: "+dst_ip +"\n"
	while (dst_port<=1000):
		tcp_ack_resp = sr1(ip/TCP(flags="A", dport=dst_port), 
		timeout = 1, verbose=0)
		if (str(type(tcp_ack_resp))=="<type 'NoneType'>"):
			#si no recibe ningún paquete el puerto está filtrado
			port_fil =  port_fil +1
		elif (tcp_ack_resp.haslayer(ICMP)):
			if(int(tcp_ack_resp.getlayer(ICMP).type)==3 and 
			int(tcp_ack_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				#Si el recibe el paquete ICMP con el tipo 3 o el tipo 
				# de codigo [1,2,3,9,10,13] el puerto está filtrado
				port_fil =  port_fil +1
		else:
			#Si no cumple ninguna de las anteriores el puerto no esta'
			#filtrado
			port_unfil =port_unfil+1
			print 'Port:' +str(dst_port).center(20)  + "\t"+'unFiltered'
		dst_port = dst_port +1
	print "There are  " +  str(port_unfil) + "  Unfiltered Ports " 
	print "There are  " +  str(port_fil) + "  Filtered Ports" +"\n" 
	print "Finish Scanning..."+"\n"
		
if (scanner== "-sF"):
	print "\n"+"TCP_FYN	 ()	"+ "	IP: "+dst_ip +"\n"
	while (dst_port<=1000):
		tcp_fyn_resp = sr1(ip/TCP(flags="F", dport=dst_port), 
		timeout = 1, verbose=0)
		if (str(type(tcp_fyn_resp))=="<type 'NoneType'>"):
			#Si no recibe ningún paquete es el puerto está filtrado
			port_fil = port_fil+1
		elif(tcp_fyn_resp.haslayer(TCP)):
			if(tcp_fyn_resp.getlayer(TCP).flags == 0x14):
				#Si recibe la bandera R el puerto está cerrado
				print 'Port:' +str(dst_port).center(20) +"\t"+'Closed'
			elif (tcp_fyn_resp.haslayer(ICMP)):
				if(int(tcp_fyn_resp.getlayer(ICMP).type)==3 and 
				int(tcp_fyn_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				#Si el recibe el paquete ICMP con el tipo 3 o el tipo 
				# de codigo [1,2,3,9,10,13] el puerto está filtrado
					port_fil = port_fil+1
		dst_port = dst_port +1
	print "There are  "+ str(port_fil)+"  Filtered and Open Ports "  
	print "\n" + "Finish Scanning..."+"\n"	
	
if (scanner== "-sU"):
	print "\n"+"TCP_UDP	 ()	"+ "	IP: "+dst_ip +"\n"
	while (dst_port<=1000):
		udp_scan_resp = sr1(ip/UDP(dport=dst_port),timeout=6, verbose=0)
		if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
			#Si no recibe un paquete este está filtrado o abierto.
			print'Port:'+str(dst_port).center(20)+"\t"+"Open | Filtered"
		elif(udp_scan_resp.haslayer(ICMP)):
			if(int(udp_scan_resp.getlayer(ICMP).type)==3):
				#Si la recibe un ICMP de tipo 3 está cerrado
				if(int(udp_scan_resp.getlayer(ICMP).code)==3):
					print'Port:'+str(dst_port).center(20)+"\t"+"Closed"
		dst_port = dst_port +1	
	print "There are  " +  str(port_closed) + "  Closed Ports "  
	print "Finish Scanning..."+"\n"			
			
if (scanner== "-sI"):
	dst_port = sys.argv[4] 					#Argumento 4 puerto a escanear
	dst_ip = sys.argv[3]						#Argumento 3 ip destino	
	zombi_ip = sys.argv[2]					#Argumento 2 ip zombi
	id_zombi = 0 						#ID de zombi
	ip=IP(dst=zombi_ip)
	print "\n"+"TCP_IDLE	 ()	"+ "	IP: "+dst_ip +"\n"
	while (dst_port<=1000):
		tcp_connect_resp = sr1(ip/TCP(dport=dst_port),timeout=0.5, 
		verbose=0)
		if(str(type(tcp_connect_resp))=="<type 'NoneType'>"):
			break		#si el puerto es filtrado, saltar while
		elif(tcp_connect_resp.haslayer(TCP)):
			if(tcp_connect_resp.getlayer(TCP).flags == 0x12):
				#si la bandera A es activa envia la bandera R 
				#par terminar la conexión
				send_rst = sr(ip/TCP(dport=dst_port, flags="R"),
				timeout=0.5, verbose=0)
				port_zombi=dst_port
				dst_port = 1026
			else:
				break	#si el puerto está cerrado saltar while
		dst_port = dst_port+1
	ip=IP(dst=dst_ip)					#creación del paquete ip
	ip_destino=IP(src = zombi_ip, dst=dst_ip)
	tcp=TCP(sport=port_zombi,flags="SA")
	tcp_destino=TCP(dport=dst_port,flags="S")
	send_rst = sr1(ip/tcp,timeout=0.5, verbose=0)
	#Envio del paquete al zombi
	if(str(type(send_rst))!="<type 'NoneType'>"):
		id_zombi=send_rst.id
		send_rest2 = sr1(ip_destino/tcp_destino, verbose=0)
	send_rst3=sr1(ip/tcp,timeout=0.5, verbose=0)
	if(str(type(send_rst3))!="<type 'NoneType'>"):
		if (int(id_zombi)-int(send_rst.id)>=2):
			print'Port:'+str(zombi_ip).center(20)+"\t"+"Open | Closed"
		else: 
			print'Port:'+str(zombi_ip).center(20)+"\t"+"Filtered"
	print "There are  " +  str(port_closed) + "  Closed Ports "  
	print "Finish Scanning..."+"\n"	

##Fuentes bibliográficas. 
##[1] http://resources.infosecinstitute.com/port-scanning-using-scapy/
##[2] http://thepacketgeek.com/scapy-p-10-emulating-nmap-functions/#port-scanner
##[3] http://nmap.org/man/es/man-port-scanning-techniques.html
##[4] http://packetlife.net/blog/2011/may/23/introduction-scapy/
##[5] http://rapid.web.unc.edu/resources/tcp-flag-key/
##[6] http://nmap.org/book/idlescan.html



