"""
* first of all I am piru the author of this code
* we are gonna need some bit manipulations functions such as ->
-- xor = x^y (0 if both bits are equal else 1) e.g. 110^101=> 011
-- right shift = x>>n (turns first n bits from the right to 0)
-- left shift= x<<n (turns first n bits from the left to 0)
-- ROTR= right shifts the first n bits from the right but insted of making them 0 use the slice from the back of the bit's end
-- chr(x,y,z)
-- Maj(x,y,z)
* ofcourse we are gonna need some bit processing before hashing
* there are some constant hexadecimal values we are going to use
* 
"""
import sys # compute the hash from system calls
import math # math calculations
import time


# bitwise or cryptographic functions I am gonna need
# the functions
ROTR=lambda x,n: (x>>n | x<< (32-n))& 0xFFFFFFFF
XOR=lambda x,y: x^y
ADDMOD=lambda a,b: (a+b)&0xFFFFFFFF
CH=lambda x,y,z: (x&y)^(~x&z)
MAJ=lambda x,y,z: (x&y)^(x&z)^(y&z)
BSX0=lambda x: ROTR(x,2)^ ROTR(x,13)^ ROTR(x,22)
BSX1=lambda x: ROTR(x,6)^ROTR(x,11)^ROTR(x,25)
SSX0=lambda x: ROTR(x,7)^ ROTR(x,18)^(x>>3) 
SSX1=lambda x: ROTR(x,17)^ ROTR(x,19)^(x>>10)


# constants we will need
CONSTANTS={
	"K8": [0x6a09e667,  0xbb67ae85, 0x3c6ef372, 0xa54ff53a,0x510e527f, 0x9b05688c,0x1f83d9ab,0x5be0cd19],
	"K64": [
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
    
}



# according to the paper preprocessing should be done 
# before the computation of hash begins
def Padding(msg):
	if isinstance(msg,str):
		msg=msg.encode("utf-8")
	l=len(msg)*8
	res="".join(f'{i:08b}' for i in msg) # store the message as a 8 bit binary 
	res+="1" # add 1
	k=(448-(l+1))%512
	res+="0"*k # append k "0" bits to the end
	res+=f"{l:064b}"  # append the orginal binaries length as a 64 bit binary to the end
	return res 


# chunk parsing each block of whole message into a chunk of size 512 each
def parse_chunks(padded_msg:str)->str:
	chunk=[]
	for i in range(0,len(padded_msg),512):
		chk=(padded_msg[i:i+512])
		chunk.append(chk)
	return chunk


# parsing the msg into 32 bit words
def parse_words(chunk):
	words=[]
	for i in range(0,len(chunk),32):
		temp=int(chunk[i:i+32],2)
		words.append(temp)
	return words


# the class for hash evaluations
class SecureHash256:
	def __init__(self,msg):
		self.msg=msg
		self.processed=self.pre_process()
		# first 8 prime numbers constant
		self.K8=CONSTANTS['K8']
		self.K64=CONSTANTS['K64']
	@property
	def hash(self):
		return self.compute_hash()

	
	def pre_process(self):
	    	res=parse_chunks(Padding(self.msg))
	    	res=[parse_words(i) for i in res]
	    	return res

	def compute_hash(self):
		H=self.K8.copy()
		message_blocks=[]
		for M in range(len(self.processed)):
			a,b,c,d,e,f,g,h=H # 8 working variables are initialized with k8
			W=[0]*64 # parsed msg for i<16
			for i in range(64):
				if i<16:
					W[i]=self.processed[M][i]
				else:
					W[i]=(SSX1(W[i-2])+W[i-7]+SSX0(W[i-15])+W[i-16])&0xFFFFFFFF
			for t in range(64):
				T1=(h+BSX1(e)+CH(e,f,g)+self.K64[t]+W[t]) & 0xFFFFFFFF
				T2=(BSX0(a)+MAJ(a,b,c)) & 0xFFFFFFFF
				h=g
				g=f
				f=e
				e=(d+T1) & 0xFFFFFFFF
				d=c
				c=b
				b=a
				a=(T1+T2) & 0xFFFFFFFF
			H=[(i+j)&0xFFFFFFFF for i,j in zip(H,[a,b,c,d,e,f,g,h])]
		return "".join(f"{x:08x}" for x in H)


# main program
if __name__=="__main__":
	
	print(f"===== your SHA256 Hash for the message  {sys.argv[1]} is =====")
	model=SecureHash256(sys.argv[1])
	print(model.hash)
