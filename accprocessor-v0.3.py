##### Checking to see if account file exists
import os.path
from typing import ByteString
file_exists = os.path.exists('accountlist.txt')
if file_exists == False:
	### Safety net for incase there are errors while creating account file
	try:
		fname = open('accountlist.txt', 'w')
		try:
			s = 'root admin sa NONE'
			fname.write(s)
		except:
			print("ERROR writing to file")
			quit()
	except:
		print("ERROR opening file")
		quit()
	finally:
		fname.close()


def genulist():

	##### Creating user file with associated properties
	acclist = open('accountlist.txt', 'r')
	alist = acclist.read()
	alist = alist.split()
	acclist.close()

	## ulist is going to be our dictionary with the 'key' being the username and then the 'value' being a list of all the properties
	ulist = dict()
	## Countprop is counting how many properties are present for each account, really just for if there needs to be another property
	countprop = 3
	for i in range(1, len(alist), countprop + 1):
		userprops = []
		for b in range(0, countprop, 1):
			userprops.append(alist[i+b])
		ulist[alist[i-1]] = userprops
	return ulist
ulist = genulist()

##### Clear command
from os import system, name
def clear(a=None):
	if name == 'nt':
		system('cls')
	else:
		system('clear')
	if a == None:
		print("Matt's Account Manager Script")
		print("")


##### Functions
def joinvar(a, b, c=None):
	if c == None:
		out = str(a),str(b)
		out = "".join(out)
		return out
	elif c == 1:
		out = str(a),str(b)
		out = " ".join(out)
		return out


def request(usrinput):
	if usrinput == "quit":
			return 'quit'

	elif usrinput == "acc" or usrinput == "ac" or usrinput == "lacc":
		j = ulist
		ulist_keys = list(j.keys())
		print(ulist_keys)

	elif usrinput == "mkacc":
		if chkprms(curusr, 'a'):
			newusr = addacc()
			if newusr != None:
				print("Account '" + newusr + "' created successfully!")
		else:
			print("Access Denied")	

	elif usrinput == "rmacc":
		if chkprms(curusr, 'a'):
			oldusr = rmacc(user)
			if oldusr != None:
				print("Account '" + oldusr + "' removed successfully!")
		else:
			print("Access Denied")
	elif usrinput == "logout":
		return 'logout'


def addacc():
	usr = input("New username: ")
	if ulist.get(usr,0) != 0:
		print("ERROR: User already exists")
		return None
	if usr == '': 
		print("ERROR: You must input a username")
		return None
	inputpass = input("New password: ")
	if inputpass == '':
		print("ERROR: You must input a password")
		return None
	ac = input("Access: ")
	if ac == '':
		print("ERROR: Must choose an access level")
		return None
	willHash = input("Encrypt Password?(y/n): ")
	salt = ''
	if willHash == '' : 
		print("ERROR: Must decide to encrypt password or not")
	if willHash == 'y' : newpass, salt = hashpass(inputpass)
	if willHash == 'n' : 
		newpass = inputpass
		salt = 'NONE'
	acclist = open('accountlist.txt', 'a')
	newacc = joinvar("\n", usr)
	newacc = joinvar(newacc, newpass, 1)
	newacc = joinvar(newacc, ac, 1)
	newacc = joinvar(newacc, salt, 1)
	acclist.write(newacc)
	acclist.close()
	return usr


def rmacc(t):
	z = input("Account name for removal: ")
	if ulist.get(z, 0) == 0:
		print("Invalid username")
		return None
	elif z == t:
		print("You cannot delete the current account")
		return None
	a_file = open("accountlist.txt", "r")
	lines = a_file.readlines()
	a_file.close()

	new_file = open("accountlist.txt", "w")
	for i in lines:
		if i.startswith(z) == False and i != '\n':
			new_file.write(i)
	new_file.close()
	return z


def chkprms(u, p):
	if curusr[1] == 'sa' or curusr[1] == p:
		return True
	elif p == 'u':
		return True
	else:
		return False


hashlength = 16
def hashpass(pw, u=None):
	import hashlib
	import os
	props = ulist.get(u,0)
	if props != 0 and u != None:
		if props[2]=='NONE' and props[0] == pw: return True
		if pw == '': return False
		salt = props[2].encode('utf-8')
		hashed = hashlib.pbkdf2_hmac(
			'sha256', # The hash digest algorithm for hmac
			pw.encode('ascii', 'backslashreplace'), # Convert the password to ascii
			salt, #Provide the salt
			100000 # It's recommended to use at least 100,000 iterations of SHA-256
		)
		# Password correct
		if str(hashed) == props[0]:
			return True

		# Password incorrect
		if str(hashed) != props[0]:
			return False
	# User doesn't exist
	if pw == '' : return '', ''
	salt = os.urandom(hashlength)
	salt2 = (str(salt)).encode('utf-8')
	hashed = hashlib.pbkdf2_hmac(
		'sha256',
		pw.encode('ascii', 'backslashreplace'),
		salt2,
		100000
	)
	return hashed, salt


##### Login
while True:
	clear()
	logged = False
	failedattempt = 0
	while logged == False:
		user = input("Username: ")
		if user == 'quit':
			clear(1)
			quit()
		pwd = input("Password: ")
		if pwd == 'quit':
			clear(1)
			quit()
		passCorrect = hashpass(pwd, user)
		if passCorrect == False:
			failedattempt += 1
			if failedattempt == 3:
				clear()
				print("Too many failed attempts")
				quit()
			#clear()
			print("Incorrect username or password. ", failedattempt, " failed attempts")
		elif passCorrect == True:
			logged = True


	##### Logged in
	clear()
	quitbool = False
	curusr = ulist[user]

	while quitbool == False:
		req = request(input(joinvar(user, ">>> ")))
		if req == 'logout': break
		if req == 'quit': 
			quitbool = True
			break
		ulist = genulist()

	if quitbool == True:
		clear(1)
		quit()