#!/usr/bin/env python3

# python3 pscanner.py
# author: Omar
#
# script uses command line arguments for values rather than setting values in the script
# python3 pscanner.py ip.address.goes.here min_port      max_port
#         sys.argv[0]   sys.argv[1]          sys.argv[2]   sys.argv[3]
#
# example: python3 pscanner.py 127.0.0.1 1 65535
#  result will scan ip 127.0.0.1 from port 1 to port 65535
#----------------------------------------------------------------------------------

# import python3 modules needed for the script
#

import sys 
import socket 
from datetime import datetime as dt


# if the number of command line arguments does not equal 4, fail, display error, exit
# python3 pscanner.py ip.address.goes.here 	min_port      max_port
#         sys.argv[0]   sys.argv[1]          sys.argv[2]   sys.argv[3]
#

#Define our target 

if len(sys.argv) != 4:
	print("\nInvalid amount of arguments.")
	print("\nSyntax: python3 pscanner.py 127.0.0.1 1 65535")
	sys.exit()


# if sys.argv[3] maximum port value is greater than 65535 fail, display error, exit
#

if int(sys.argv[3]) > 65535:
	print("\nInvalid maximum port number")
	print("\nSyntax: python3 pscanner.py 127.0.0.1 1 65535")
	sys.exit()

# if sys.argv[2] minimum port value is less than 1 fail, display error, exit
#

if int(sys.argv[2]) < 1:
	print("\nInvalid minimum port number")
	print("\nSyntax: python3 pscanner.py 127.0.0.1 1 65535")
	sys.exit()

# if unable to resolve sys.argv[1] hostname to an ip address before port scan
# fail, catch execption, display error, exit
#

for ip in sys.argv[1]:
	try: 
		ip = socket.gethostbyname(sys.argv[1])  #Translate hostname to IPv4 to DNS resolve 		
	except socket.gaierror:  
		print("\n Unable to resolve " + sys.argv[1] + " to an IP address!")
		sys.exit()
	

# BEGIN MAIN SCANNING FUNCTION
# If everything above has not exited due to an error - lets get to work!
# on screen display of what the script is doing and the values
	
#Add a pretty banner

print("-" * 50)
print("\nScanning Target: " + str(sys.argv[1]))
print("	       Target IP: " + ip)
print("		Min port: " + str(sys.argv[2]))
print("		Max port: " + str(sys.argv[3]))
print("	    Time started: " + str(dt.now()))
print("-" * 50)


# begin port scanning based on min_port and max_port defined at top of script
#

for port in range(int(sys.argv[2]),int(sys.argv[3])):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		socket.setdefaulttimeout(0.5) # 0.5 second timeout
		result = s.connect_ex((ip,port)) #returns an error indicator 
		if result == 0:
			print("Port {} is open".format(port))
		s.close()

# Catch error during the port scan
  #
	except KeyboardInterrupt:
		print("Exiting program.")
		sys.exit()

# Catch error during the port scan
  #   	
	except socket.error: # no connection to the target address 
		print("Couldn't connect to server.")
		sys.exit()
