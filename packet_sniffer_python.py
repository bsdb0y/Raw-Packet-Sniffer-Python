import socket, sys
from struct import *
import fcntl
import ctypes



try:
	interface = sys.argv[1]
except:
	print "Usage: sudo python packet_sniffer_python.py <interface_name>"
	exit()



class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]

file = open("sniff_logger_py.txt","w")

 
#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b
 
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */

#http://elixir.free-electrons.com/linux/latest/source/include/uapi/linux/sockios.h --> This is link where you will get these flags values .
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_PROMISC = 0x100

ETH_P_ALL = 0x0003
current_flags = 0



try:
	s = socket.socket( socket.PF_PACKET , socket.SOCK_RAW , socket.ntohs(ETH_P_ALL))
	try:
		ifr = ifreq()
		ifr.ifr_ifrn = interface
		fcntl.ioctl(s, SIOCGIFFLAGS, ifr) # get the flags
		ifr.ifr_flags |= IFF_PROMISC # add the promiscuous flag
		fcntl.ioctl(s, SIOCSIFFLAGS, ifr) # update
	except Exception as err:
		print "Error: " + str(err)
except socket.error , msg:
	print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	sys.exit()
print "Writing decoded packet to sniff_logger_py.txt\n"
count = 1
while count:
	packet = s.recvfrom(65565)

	#packet string from tuple
	packet = packet[0]

	#parse ethernet header
	eth_length = 14  #Ethernet Header is of 14 bytes in length . 

	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH' , eth_header) #unpack the raw data  into structure according to in c struct ethdr .
	eth_protocol = socket.ntohs(eth[2])
	file.write("\n")
	file.write("\n\nEthernet Header\n")
	file.write('|-Destination MAC : ' + eth_addr(packet[0:6])) 
	file.write("\n")
	file.write('|-Source MAC : ' + eth_addr(packet[6:12]))
	
	file.write("\n")
	file.write( '|-Protocol : ' + str(eth_protocol))
	
	file.write("\n")
	#Parse IP packets, IP Protocol number = 8
	if eth_protocol == 8 :
		#Parse IP header
		#take first 20 characters for the ip header
		ip_header = packet[eth_length:20+eth_length]
		 
		#now unpack them :)
		iph = unpack('!BBHHHBBH4s4s' , ip_header)

		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF

		iph_length = ihl * 4

		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8])
		d_addr = socket.inet_ntoa(iph[9])
		file.write("\nIP Header\n")
		file.write("TTL: " + str(ttl))
		file.write("\niph lenght: " + str(iph_length))
		file.write("\n|-version:" + str(version))
		file.write("\n|-protocol: " + str(protocol))
		file.write("\n|-version IHL: " + str(version_ihl))
		file.write("\n|-Src Addr: " + str(s_addr))
		file.write("\n|-Dest Addr: " + str(d_addr))

		#TCP protocol
        	if protocol == 6:
			t = iph_length + eth_length
			tcp_header = packet[t:t+20]

			#now unpack them 
			tcph = unpack('!HHLLBBHHH' , tcp_header)

			source_port = tcph[0]
			dest_port = tcph[1]
			sequence = tcph[2]
			acknowledgement = tcph[3]
			doff_reserved = tcph[4]
			tcph_length = doff_reserved >> 4
			file.write("\n\nTCP Packet")

			file.write('\nSource Port : ' + str(source_port))
			file.write('\nDest Port : ' + str(dest_port))
			file.write('\nSequence Number : ' + str(sequence))
			file.write('\nAcknowledgement : ' + str(acknowledgement))
			file.write('\nTCP header length : ' + str(tcph_length))


        	#ICMP Packets
		elif protocol == 1:
			u = iph_length + eth_length
			icmph_length = 4
			icmp_header = packet[u:u+4]

			#now unpack them
			icmph = unpack('!BBH' , icmp_header)

			icmp_type = icmph[0]
			code = icmph[1]
			checksum = icmph[2]
			file.write("\n\nICMP Packet")
			file.write('\nType : ' + str(icmp_type)) 
			file.write('\nCode : ' + str(code))
			file.write('\nChecksum : ' + str(checksum))

        	#UDP packets
        	elif protocol == 17 :
			u = iph_length + eth_length
			udph_length = 8
			udp_header = packet[u:u+8]

			#now unpack them
			udph = unpack('!HHHH' , udp_header)

			source_port = udph[0]
			dest_port = udph[1]
			length = udph[2]
			checksum = udph[3]
			file.write("\n\nUDP Packet")
			file.write('\nSource Port : ' + str(source_port)) 
			file.write('\nDest Port : ' + str(dest_port))
			file.write('\n Length : ' + str(length))
			file.write('\n Checksum : ' + str(checksum))


			#some other IP packet like IGMP
		else :
			print 'Protocol other than TCP/UDP/ICMP'





file.close()
ifr.ifr_flags ^= IFF_PROMISC # mask it off (remove)
fcntl.ioctl(s, SIOCSIFFLAGS, ifr) # update

