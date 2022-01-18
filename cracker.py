from pwn import *
import sys

if len(sys.argv) != 2:
	print("Invalid arguments!")
	print(">> {} <sha256sum>".format(sys.argv[0]))
	exit()

wanted_hash = sys.argv[1]
password_file = "rockyou.txt" #put your wordlist here and rename it if you want
attempts = 1

with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p:
	with open(password_file, "r", encoding="latin-1") as password_list:
		for password in password_list:
			password = password.strip("\n").encode('latin-1')
			#print(attempts, password)
			password_hash = sha256sumhex(password)
			#print(attempts, password_hash)
			password_status = p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
			#print(attempts, password_status)
			if password_hash == wanted_hash:
				p.success("Password hash found after {} attempts! {} hashes to {} \n\n".format(attempts, password.decode('latin-1'), password_hash))
				exit()
			attempts += 1
		p.failure("Password hash not found!\n")
