import random
import sympy as sp
from math import gcd
from sympy import mod_inverse as findModInverse
  
#Define the domain variables common to all.
# q = 17
a , b = 1, 4   
mod = 23
n = 29
G = (7,3)   
 
#Function to multiply a point by a scalar on an elliptic curve
def pointMultiply(P, k, a, b, mod): 
    # Initialize the result as the point at infinity (the identity element)
    result = None
    
    # Convert k to binary and iterate over each bit
    k_bin = bin(k)[2:]
    
    for bit in k_bin:
        # Double the point (result = 2 * result)
        result = pointAddition(result, result, a, b, mod)
        if bit == '1':
            # Add P to the result if the current bit is 1 (result = result + P)
            result = pointAddition(result, P, a, b, mod)
    
    return result

# Function to calculate the point addition Q + P on an eliptic curve
def pointAddition(P, Q, a, b, mod): 
    # Handle the case of the point at infinity
    if P is None:
        return Q
    if Q is None:
        return P
    
    # Unpack the points
    x1, y1 = P
    x2, y2 = Q
    
    # Point doubling
    if P == Q:
        if y1 == 0:
            return None  # The point at infinity
        # Calculate the slope (lambda) of the tangent
        slope = (3 * x1**2 + a) * sp.mod_inverse(2 * y1, mod) % mod
    else:
        # If the points are distinct, ensure that the slope is defined
        if x1 == x2:
            return None  # The point at infinity
        # Calculate the slope (lambda) between the points
        slope = (y2 - y1) * sp.mod_inverse(x2 - x1, mod) % mod
    
    # Calculate the new point coordinates
    x3 = (slope**2 - x1 - x2) % mod
    y3 = (slope * (x1 - x3) - y1) % mod
    
    return (x3, y3)

# Function for hashing the message
def hashing(message):
	import hashlib
	return int(hashlib.sha512(str(message).encode("utf-8")).hexdigest(), 16)

def create_private_key():
    d = random.randint(1, n-1)
    return d

def create_public_key(private_key):
    publicKey = pointMultiply(G, private_key, a, b, mod) #Compute Public Key as Q = dG, where d is private Key
    return publicKey 

def sign_message(private_key, message): 
	r = None ; t = None ; s = 0
	while r == None or s == 0:
		k = random.randint(1, n-1)
		P = pointMultiply(G , k , a , b , mod) 
		r = P[0] % n
		t = findModInverse(k, n)
		# print("t ",t)
		e = hashing(message) 
		s = (e+private_key*r)*t % n 
	return (r,s)


def verify_signature(public_key, message, signature):
	if(signature[0] > n-1 or signature[1] > n-1):
		return "Bad signature"  
	e = hashing(message)
	r , s = signature[0], signature[1]
	w = findModInverse(s, n)  
	u1 = e*w %n
	u2 = r*w %n
	u1G = pointMultiply(G , u1 , a , b , mod) 
	u2Q = pointMultiply(public_key , u2 , a , b , mod)
	X = pointAddition(u1G, u2Q, a, b, mod)
	if X == (0,0):
		return False #Return False not authentic
	else:
		v = X[0] % n 
		return True if v == r else False #Return True if authentic else false


# privateK = create_private_key()
# publicK = create_public_key(privateK)
# print("Private Key: ", privateK ,'\n',"Public Key: ", publicK)

# message = "Hello"
# signature = sign_message(privateK,message)
# print("Signature: ", signature)
# print(verify_signature(publicK,message, signature))
 
 