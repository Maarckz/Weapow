#!/usr/bin/env python3
version = "v4.12-dev"

import os
import re
import sys
import signal
import socket
import struct
import requests
import ipaddress
import time as t
import getpass as g
import multiprocessing
import threading as th
from scapy.all import *
import http.server as hs
import socketserver as ss
from bs4 import BeautifulSoup 
from requests.exceptions import SSLError
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor as exx


###########################################################
## BANNER PRINCIPAL DO PROGRAMA, EXIBINDO A VERSÃO ATUAL ##
###########################################################
bann = f'''\033[1;33m
888  888  888  .d88b.   8888b.  88888b.   .d88b.  888  888  888
888  888  888 d8P  Y8b     "88b 888 "88b d88""88b 888  888  888
888  888  888 88888888 .d888888 888  888 888  888 888  888  888
Y88b 888 d88P Y8b.     888  888 888 d88P Y88..88P Y88b 888 d88P
 "Y8888888P"   "Y8888  "Y888888 88888P"   "Y88P"   "Y8888888P"
\033[0;31m (\\ (\\\033[m \033[1;35m                         \033[m\033[1;33m888\033[m                 \033[7;32m{version}\033[m
\033[0;31m ( ^.^)\033[m\033[1;35m-------------------------\033[m\033[1;33m888\033[m 
\033[0;31m O_(")(")  \033[m                     \033[1;33m888\033[m\n           '''


####################################################
## GRUPO DE VARIÁVEIS QUE SÃO REPETIDAS NO CODIGO ##
####################################################
press = '\033[7;31m(Pressione qualquer tecla para voltar ao menu inicial)\033[m'
Ctrl_C = 'Você pressionou Ctrl+C para interromper o programa!'
dir = 'mkdir -p ARQ'
SIGNALHOSTDISCOVERY = True

#########################################
## FUNÇÃO PARA INTERRUPÇÃO DO PROGRAMA ##
#########################################
def handler(signum, frame):
        global pool
        try:
            pool.terminate()
        except Exception as e:
            pass
        except KeyboardInterrupt:
            pass
        finally:
            exit(0)

signal.signal(signal.SIGINT, handler)

#############################################################
## FUNÇÃO QUE BUSCA INTERFACES E CRIA UMA LISTA DE SELEÇÃO ##
#############################################################
def interfaces():

    ########################################
    ## CRIA UM MENU DE INTERFACES DE REDE ##
    ########################################
    try:
        
        interfaces = []
        for interface_name in os.listdir('/sys/class/net'): 
            
            if interface_name == 'lo':
                continue
            interfaces.append(interface_name)
       
        if not interfaces:
            print("Nenhuma interface de rede encontrada.")
            input(press)
            main()

        ###################################################    
        ## PARA CADA INTERFACE, E CRIADO UM ITEM NO MENU ##
        ###################################################
        print("\nSelecione a interface de rede:")
        for i, interface in enumerate((interfaces), 1):
            print(f"\033[0;34m[{i}]\033[m - {interface}")

        while True:
            try:
                escolha = int(input("Digite a opção: "))
                if escolha < 0 or escolha > len(interfaces):
                    raise ValueError
                break
                if escolha == 0:
                    main()
            except ValueError:
                print("Opção inválida.")
        
        ###################################
        ## CASO SEJA "0" RETORNA AO MENU ##
        ###################################
        if escolha == 0:
            main()
        
        selected_interface = interfaces[escolha - 1]

        return selected_interface

    except KeyboardInterrupt:
        print('\n'+Ctrl_C)
        quit()

#=======================================================================================
#############################################
## FUNÇÃO PARA DESCOBERTA DE HOSTS NA REDE ##
#############################################
def host_discovery():

    #######################
    ## VARIAVEIS GLOBAIS ##
    #######################
    responses = set()  # Usar um conjunto para evitar duplicações
    existing_hosts = set() 

    def checksum(source_string):
        sum = 0
        count_to = (len(source_string) // 2) * 2
        count = 0
        while count < count_to:
            this_val = source_string[count + 1] * 256 + source_string[count]
            sum += this_val
            sum &= 0xffffffff
            count += 2
        if count_to < len(source_string):
            sum += source_string[len(source_string) - 1]
            sum &= 0xffffffff
        sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)
        answer = ~sum
        answer &= 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

# Função para criar um pacote ICMP
    def create_packet(id):
        header = struct.pack('bbHHh', 8, 0, 0, id, 1)
        data = 192 * 'Q'
        my_checksum = checksum(header + data.encode())
        header = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), id, 1)
        return header + data.encode()

    # Função ping (extraído do "ping.c")
    def ping(addr, timeout=1):
        try:
            # Cria um socket ICMP e estabelece uma conexão
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            packet_id = 1
            packet = create_packet(packet_id)
            s.connect((addr, 80))
            s.sendall(packet)
            s.close()
            return True
        except PermissionError:
            pass
        except Exception as e:
            print(e)
            
    # Função para resolver hostname via socket
    def hostname_resolv(ips):
        for ip in ips:
            try:
                socket.setdefaulttimeout(5)  # Define timeout para operações de socket
                hostname = socket.gethostbyaddr(ip)
                with open('ARQ/hostnames.txt', 'a') as f:
                    f.write(f'+ {ip} - {hostname[0]}\n')
                socket.setdefaulttimeout(None)  # Reseta timeout após resolução bem-sucedida
            except (socket.gaierror, OSError, Exception):
                pass
            finally:
                socket.setdefaulttimeout(None)  # Sempre reseta o timeout para evitar efeitos indesejados

        print("Terminado:", t.strftime("%X %x"))

    # Função de envio
    def envio(addr):
        print("Iniciando Envio de Pacotes:", t.strftime("%X %x"))
        try:
            for ip in addr:
                ping(str(ip))
                t.sleep(0.00015)
            
            t.sleep(2)
            
            global SIGNALHOSTDISCOVERY
            
            SIGNALHOSTDISCOVERY = False
            ping('127.0.0.1')
            
            for response in sorted(responses):
                ip = struct.unpack('BBBB', response)
                ip = f"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}"
                
                if ip not in existing_hosts:  # Verifica se o IP não está em existing_hosts
                    with open('ARQ/discovery.txt', 'a') as file:
                        file.write(f'{ip}\n')
                    existing_hosts.add(ip)  # Adiciona IP descoberto a existing_hosts
                    
            print(f'\033[7;31m[+] {len(responses)} Hosts-UP! Verifique o arquivo "discovery.txt"\033[m')
            print("Terminando, tentando fazer resolução de HostName.", t.strftime("%X %x"))
            if ips:
                t_hostname = th.Thread(target=hostname_resolv, args=[ips])
                t_hostname.start()
            else:
                print("Não foi possível gerar a lista de IPs.")
        except KeyboardInterrupt:
            print('\n' + Ctrl_C)
            quit()

    # Função para escutar respostas ICMP
    def listen(responses, ip_network):
        global SIGNALHOSTDISCOVERY
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
            s.settimeout(10)
            s.bind(('', 0))
            while SIGNALHOSTDISCOVERY:
                try:
                    packet = s.recv(2048)[:20][-8:-4]  
                except TimeoutError:
                    packet = None  

                if packet is not None and ipaddress.ip_address(packet) in ip_network:
                    ip = ipaddress.ip_address(packet)
                    
                    if ip not in existing_hosts:  # Verifica se o IP não está em existing_hosts
                        print(ip)
                        responses.add(packet)
                        existing_hosts.add(ip)  # Adiciona IP descoberto a existing_hosts
                        
                        with open('ARQ/hosts.txt', 'a') as file:
                            file.write(f'{ip}\n')
                
            s.close()

    
    # Entrada do endereço de IP
    ips = input('Digite a faixa de IP (Ex: xx.xx.xx.xx/xx): ')

    rede = ipaddress.ip_network(ips, strict=False)
    ips = list(map(str, rede.hosts()))

    # Cria pasta "ARQ" e remove arquivos antigos
    os.system('mkdir -p ARQ')
    os.system('rm ARQ/hosts.txt 2>/dev/null')
    os.system('rm ARQ/hostnames.txt 2>/dev/null')
    os.system('rm ARQ/discovery.txt 2>/dev/null')

    print('\n\033[7;32mAguarde ...\033[m')

    # Thread para escutar pacotes ICMP
    t_server = th.Thread(target=listen, args=[responses, rede])
    t_server.start()

    # Thread para enviar pacotes ICMP
    t_ping = th.Thread(target=envio, args=[rede])
    t_ping.start()



    

#=======================================================================================
############################################
## PORTAS A SEREM VERIFICADAS NO PORTSCAN ##
############################################
PORTAS_PRINCIPAIS = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211,
    212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617,
    625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001,
    1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055,
    1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095,
    1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166,
    1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443, 
    1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900,
    1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068,
    2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601,
    2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211,
    3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809,
    3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446,
    4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414,
    5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922,
    5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567,
    6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777,
    7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194,
    8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8728, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100,
    9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004,
    10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002,
    15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502,
    24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784,
    32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400,
    49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331,
    64623, 64680, 65000, 65129, 65389
]

########################################################################
## FUNÇÃO QUE REALIZA A TENTATIVA DE CONEXÃO DE ACORDO COM HOST/PORTA ##
########################################################################
def scan(host, porta):
        try:
            l = len(str(porta))
            espaco = " " * (10 - l)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.5)
                if s.connect_ex((host, int(porta))) == 0:
                    with open("ARQ/portscan.txt", "a") as f:
                        try:
                            service = socket.getservbyport(porta)
                            print(f"{str(porta)} / TCP{espaco}{service}")
                            print(f"{str(porta)} / TCP{espaco}{service}", file=f)
                        except socket.error:
                            print(str(porta) + f" / TCP")
                            print(str(porta) + f" / TCP", file=f)
        except Exception as e:
            pass

##################################################################################
## ESTA FUNÇÃO FAZ UM PORTSCAN DE ACORDO COM A LISTA GERADO PELO HOST DISCOVERY ##
##################################################################################
def big_scan():

    ##############################################################
    ## FUNÇÃO PRINCIPAL QUE REALIZA O GERENCIAMENTO DO PORTSCAN ##
    ##############################################################
    def uniq(host):
        try:
            with open("ARQ/portscan.txt", "a") as f:
                print("\n[+] Host: " + host)
                print("\n[+] Host: " + host, file=f)
                print("PORTA          SERVIÇO")
                print("PORTA          SERVIÇO", file=f)
            host_ip = socket.gethostbyname(host)

        except socket.gaierror:
            return

        global pool
        pool = multiprocessing.Pool(processes=220)

        try:
            for porta in PORTAS_PRINCIPAIS:
                pool.apply_async(scan, args=(host_ip, porta))

            pool.close()
            pool.join()
        
        except Exception as e:
            pool.terminate()
            pool.join()

    ###########################################################
    ## INTERAÇÃO COM O USUÁRIO PARA DIRECIONAMENTO DA FUNÇÃO ##
    ###########################################################
    os.popen('rm ARQ/portscan.txt 2>/dev/null')
    sit_scan = input('Deseja utilizar um (H)ost ou a (L)ista? (H/L): ')

    if sit_scan.lower() == 'h':
        host = input("Digite o endereço IP ou domínio: ")
        uniq(host)
    elif sit_scan.lower() == 'l':
        with open('ARQ/hosts.txt','r') as file:
            for line in file:
                uniq(line.strip())

#===============================================================================
#===============================================================================
#===============================================================================
#===============================================================================
#===============================================================================
def world_scan():
    #####################################################
    ## DEFINE O NÚMERO DE THREADS E CRIA UM "SEMAFORO" ##
    #####################################################
    MAX_THREADS = 600
    thread_semaphore = threading.Semaphore(MAX_THREADS)

    ########################################################################
    ## FUNÇÃO QUE REALIZA A TENTATIVA DE CONEXÃO DE ACORDO COM HOST/PORTA ##
    ########################################################################
    def scan(ip,porta):
        try:
            host = str(ip)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, porta))
            if result == 0:
                print(f"Port {porta} is open on {host}")
                with open(f'World_Port_{porta}.txt','a') as f:
                    print(host, file=f)
            sock.close()
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
        finally:
            ############################################################
            ## Sempre libere o semáforo, mesmo se ocorrer uma exceção ##
            ############################################################
            thread_semaphore.release()

    def worker(ips,porta):
        threads = []
        for ip in ips:
            ## Adquire o semáforo antes de criar uma nova thread ##
            thread_semaphore.acquire()
            t = threading.Thread(target=scan, args=(ip,porta))
            t.start()
            threads.append(t)
        
        # Aguardar todas as threads terminarem
        for t in threads:
            t.join()

    ips = input('Digite a faixa de IP (Ex: xx.xx.xx.xx/xx): ')
    porta = int(input('Qual porta? '))

    # CRIA A REDE DE ACORDO COM A ENTRADA DO USUÁRIO
    network = ipaddress.ip_network(ips, strict=False)
    ips_list = list(map(str, network.hosts()))

    # Dividindo a lista de IPs em partes para cada processo
    num_processes = multiprocessing.cpu_count()
    chunk_size = len(ips_list) // num_processes
    chunks = []
    for i in range(0, len(ips_list), chunk_size):
        chunks.append(ips_list[i:i+chunk_size])

    # Iniciando a barra de progresso fora do loop de chunks
    total_ips = 0
    for chunk in chunks:
        total_ips += len(chunk)


    # Iniciando processos para escanear em paralelo
    processes = []
    for chunk in chunks:
        p = multiprocessing.Process(target=worker, args=(chunk,porta))
        p.start()
        processes.append(p)

    # Aguardando todos os processos terminarem
    for p in processes:
        p.join()



#=======================================================================================
######################################################################
## ENVIA UMA CONEXÃO VIA NETCAT PARA RETORNAR UM POSSÍVEL CABEÇALHO ##
######################################################################
def nc_get():
    os.popen('rm ARQ/HEAD/* 2>/dev/null')
    os.makedirs("ARQ/HEAD", exist_ok=True)

    print('No código, existe a função nc(), mais lenta e verifica todas as portas.')

    def get(host, porta, servico):
        try:
            comando = f'echo -e "\n" | nc -vn -w 10 {host} {porta} 2>&1 | tee'
            resultado = os.popen(comando).read()
            caminho_arquivo = f"ARQ/HEAD/{host}"

            with open(caminho_arquivo, "a") as arquivo_respostas:
                arquivo_respostas.write(f"[+] Host: {host}    Porta: {porta}    Serviço: {servico}\t\t\n{resultado}\n")
                print(f"[+] Host: {host}    Porta: {porta}    Serviço: {servico}\t\t\n{resultado}\n")

        except Exception as e:
            print(f"Erro ao executar o comando nc: {e}")
    with open("ARQ/portscan.txt", "r") as arquivo:
        linhas = arquivo.read().strip().split('\n')
        for linha in linhas:
            if '[+] Host:' in linha:
                host = linha.split(':')[-1].strip()
            elif 'PORTA' not in linha and '/' in linha:
                porta, servico = map(str.strip, linha.split('/')[0:2])
                t = th.Thread(target=get, args=(host, porta, servico))
                t.start()

    input(press)
    main()



#=======================================================================================
###########################################################################
## VERIFICA SE EXISTE RESPOSTA "HTTP" OU "HTTPS" APOS O COMANDO "nc -vz" ##
###########################################################################
def http_finder():

    ###################################################
    ## ESTA FUNÇÃO FAZ O DOWNLOAD DO SITE ENCONTRADO ##
    ###################################################
    def wget_pg(ip, porta):
        os.system(f"rm ARQ/WEB/{ip}.html")
        os.system(f'wget --no-check-certificate --mirror --convert-links --adjust-extension --page-requisites --timeout=10 http://{ip}:{porta} -P ARQ/WEB/')
        os.system(f'chmod 777 -R ARQ/WEB/{ip}')

    for ip in os.listdir("ARQ/HEAD"):
        arquivo = os.path.join("ARQ/HEAD", ip)

        if os.path.isfile(arquivo):
            with open(arquivo, 'r') as arquivo:
                conteudo = arquivo.readlines()
                servico_web_encontrado = False
                porta = None
                for linha in conteudo:
                    match = re.search(r'Porta: (\d+)', linha)
                    if match:
                        porta = match.group(1)
                    if "http" in linha.lower() or "https" in linha.lower():
                        servico_web_encontrado = True
                        break
                if servico_web_encontrado:
                    thread = th.Thread(target=wget_pg, args=(ip, porta))
                    thread.start()
    for thread in th.enumerate():
        if thread != th.current_thread():
            thread.join()
    input(press)
    main()


#=======================================================================================          
def cert_subdomain():
    target_domain = input('Digite o dominio: ')
    target = target_domain.replace('www.', '').split('/')[0]

    try:
        req = requests.get(f"https://crt.sh/?q=%.{target}&output=json")
        req.raise_for_status()
    except requests.RequestException:
        print("[X] Information not available!")

    subdomains = sorted({value['name_value'] for value in req.json()})

    print(f"\n[!] TARGET: {target} [!] \n")

    for subdomain in subdomains:
        print(subdomain)


#=======================================================================================
def link():

    def crawl(url):
        try:
            response = requests.get(url)

        except SSLError as e:
            print(f"SSLError: {e}")
            return []

        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            links = soup.find_all('a')
            hrefcode = {urljoin(url, link['href']) for link in links if 'href' in link.attrs}
            return hrefcode

        return []

    def ext_info(url):
        durls = []
        emails = set()
        tel = set()
        forms = []
        subdomains = set()

        try:
            response = requests.get(url)
        except SSLError as e:

            print(f"SSLError: {e}")
            return durls, emails, tel, forms, subdomains

        except requests.exceptions.RequestException as e:
            print(f"RequestException: {e}")
            return durls, emails, tel, forms, subdomains

        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')

            for link in soup.find_all('a'):
                href = link.get('href')
                
                if link is soup.find('id'):
                    print(link)

                elif link is not None:
                    try:
                        if href and href.startswith('/') or href.startswith('?'):
                            durls.append(urljoin(url, href))

                        else:
                            print(href)

                    except AttributeError as e:
                        print(link,href,e)

            for link in soup.find_all('a'):
                href = link.get('href')

                if href:
                    if href.startswith("mailto:"):
                        emails.add(href[7:])

                    elif href.startswith("tel:") or "phone=" in href:
                        tel.add(href[4:])

            for form in soup.find_all('form'):
                forms.append(url)

            for link in soup.find_all('a'):
                href = link.get('href')

                if href:
                    parsed_uri = urlparse(href)
                    domain = '{uri.netloc}'.format(uri=parsed_uri).split(':')[0]
                    subdomains.add(domain)

        return durls, emails, tel, forms, subdomains #######################################  LEMBRAR COMO FUNCIONA

    def process_url(url):
        visit_urls = set()

        if url in visit_urls:
            return

        visit_urls.add(url)
        divurls = crawl(url)
        print("\n\nEfetuando WebCrawling em ", url)

        for divurl in sorted(divurls):
            print('\n\033[0;31m============================================================================================>>\033[m',t.strftime("\033[7;32m %d/%m/%y \033[m"))
            print(divurl)
            print('\033[0;31m============================================================================================>>\033[m',t.strftime("\033[7;32m %H:%M:%S \033[m"))

            durls, emails, tel, forms, subdomains = ext_info(divurl)

            if durls:
                print('\nURLs INTERNAS:')
                for url in durls:
                    print(url)
                    try:
                        links(url)
                    except requests.exceptions.ConnectionError as err:
                        pass
            if emails:
                print('\nEMAILS:')
                for email in emails:
                    print(email)
            if tel:
                print('\nTELEFONES:')
                for phone in tel:
                    print(phone)
            if forms:
                print('\nFORMULÁRIOS:')
                for form in forms:
                    print(form)
            if subdomains:
                print('\nSITES:')
                for subdomain in subdomains:
                    print(subdomain)
            if durls:
                print('\nURLs INTERNAS:')
                for url in durls:
                    print(url)

    def links(target):
        url_process = ['http://' + target]
        url_atual = url_process.pop()
        process_url(url_atual)
        with open(f'Crawl/{target}_craw.txt', 'w') as f:
            while url_process:
                os.dup2(f.fileno(), 1)
                process_url(url_atual)
                os.dup2(os.dup(2), 1)

    interface = interfaces()

    os.popen('rm -rf Crawl 2>/dev/null')
    t.sleep(1)
    os.popen('mkdir Crawl 2>/dev/null') 

    sit_scan = input('Deseja utilizar um (H)ost ou a (L)ista? (H/L): ')

    if (sit_scan.lower() == 'h'):
        target = input('Digite o endereço do site: (site.com)\n')
        links(target)

    elif (sit_scan.lower() == 'l'):
        for ip in os.listdir("ARQ/WEB"):
            parse_ip = ip.split(':')
            result = os.system(f'ping -c 3 -W 1 -I {interface} {parse_ip[0]} > /dev/null')
            if result == 0:
                links(ip)
            nsit = input(f'A busca em {ip} terminou. Deseja continuar? (S/N):  ')
            if nsit.lower() == 's':
                pass
            else:
                break


#=======================================================================================
##################################################################
## FAZ UMA VERIFICAÇÃO NOS SITES BAIXADOS, BUSCANDO FORMULÁRIOS ##
##################################################################            
def auto_web():
    ips = os.popen(r'grep -iR -A 5 "<form" ARQ/WEB | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u').read().split()

    try:
        #########################################################
        ## FAZ UMA VARREDURA NO ARQUIVO QUE TIVER "index.html" ##
        #########################################################
        for ip in ips:
            caminho_html = f'ARQ/WEB/{ip}/index.html'
            with open(caminho_html, 'r', encoding='utf-8') as arquivo:
                conteudo_html = arquivo.read()
                soup = BeautifulSoup(conteudo_html, 'html.parser')
                formularios = soup.find_all('form', {'action': True, 'method': True})

                if ip and formularios:
                    print('---------------------------------------------------------')
                    print(f'\nAnalisando {ip}:\n')
                    soup = BeautifulSoup(conteudo_html, 'html.parser')
                    formularios = soup.find_all('form', {'action': True, 'method': True})

                    for formulario in formularios:
                        print(f'Atributo action: {formulario["action"]}')
                        print(f'Atributo method: {formulario["method"]}')
                        print(f'Conteúdo do formulário:')
                        print(formulario.prettify())
                        print('---------------------------------------------------------\n')

        ########################################################
        ## FAZ UMA VARREDURA NO ARQUIVO QUE TIVER "index.php" ##
        ########################################################
        for ip in ips:
            caminho_html = f'ARQ/WEB/{ip}/index.php'
            with open(caminho_html, 'r', encoding='utf-8') as arquivo:
                conteudo_html = arquivo.read()
                soup = BeautifulSoup(conteudo_html, 'html.parser')
                formularios = soup.find_all('form', {'action': True, 'method': True})

                if ip and formularios:
                    print('---------------------------------------------------------')
                    print(f'\nAnalisando {ip}:\n')
                    soup = BeautifulSoup(conteudo_html, 'html.parser')
                    formularios = soup.find_all('form', {'action': True, 'method': True})

                    for formulario in formularios:
                        print(f'Atributo action: {formulario["action"]}')
                        print(f'Atributo method: {formulario["method"]}')
                        print(f'Conteúdo do formulário:')
                        print(formulario.prettify())
                        print('---------------------------------------------------------\n')

    except FileNotFoundError:
        pass
    input("Pressione Enter para continuar...")
    main()


#=======================================================================================
def backup():
    print("Este processo poderá levar MUITO tempo dependendo da quantidade de arquivos.")
    sit_bak = input('Deseja realmente fazer BKP do usuário desta estação? (S/N) ')
    try:
        if(sit_bak.lower() == "s"):
            dir = input("Digite o diretório a ser feito o BKP:\n")
            print('Fazendo BACKUP ...')
            t.sleep(2)
            os.system(f'cp -v -r {dir} /home/$USER/Backup')
        else:
            input(press)
            main()
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)


#=======================================================================================
def clonar():
    '''
    df -h
umount -t ext4 /dev/sdx && mkfs.ext4 /dev/sdx
	dd if=/deb/sdx of=/dev/sdy bs=1M conv=noerror
sudo blkid
sudo nano /etc/fstab
    '''
    pass


#=======================================================================================
def cron():
    print('''
Para configurar uma rotina C[R]ON:

\033[1;33m*  *  *  *  *  /usr/bin/python3 /caminho/do/script.*\033[m
\033[0;31m-  -  -  -  -     |                                |\033[m
\033[0;31m|  |  |  |  |     +---\033[m Caminho do Executável\033[m       \033[0;31m+---\033[m Extensão do arquivo a ser Executado. Ex: .sh .c .py
\033[0;31m|  |  |  |  |
\033[0;31m|  |  |  |  +----------------------\033[m Dia da Semana (0-6) [Sendo 0 = Domingo]
\033[0;31m|  |  |  +-------------------------\033[m Mês (1-12)
\033[0;31m|  |  +----------------------------\033[m Dia do Mês (1-31)
\033[0;31m|  +-------------------------------\033[m Hora (0-23)
\033[0;31m+----------------------------------\033[m Minutos (0-59) se quiser a cada 15min use: '/15'

Exemplo:
\033[7;33m*/15 * * * * /usr/bin/python3 /caminho/do/weapow.py\033[m   [A cada 15min EXEC o arquivo weapow.py usando Python3]
\033[7;33m30 15 14 6 * /tmp/backup.sh\033[m                        [No dia 14JUN às 15:30 EXEC o backup.sh]


Você pode conferir a alteração com o comando: "\033[0;34m$ crontab -e\033[m"

''')
    sit_cron = input("Deseja substituir as configurações do C[R]ON? (S/N)")
    if(sit_cron.lower() == "s"):
        try:
            enter = input("Digite a entrada do C[R]ON:\n")
            os.system(f'echo "{enter}" | crontab -')
            print('C[R]ON configurado corretamente.')
            input(press)
            main()
        except TypeError:
            print("Faltam [Argumentos] para entrada")
            input(press)
            main()
    else:
        input(press)
        main()


#=======================================================================================
def finder():
    try:
        find = str(input('Digite o arquivo que deseja encontrar: '))
        print('Procurando com FIND:')
        print('==================================================================================\n')
        os.system(f' find / -name {find} 2>/dev/null | grep {find}')
        print('Procurando com GREP:')
        print('==================================================================================\n')
        os.system(f' grep -iRl {find} / 2>/dev/null')
        print('\n==================================================================================')
        print('Fim da busca!\n')
        input(press)
        main()
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)


#=======================================================================================
def infosys():
    try:
        output = ''

        output += '\n'
        output += 'WHOAMI =======================================================\n'
        output += '            User: {}'.format(os.popen('whoami').read())
        output += os.popen('hostnamectl').read()
        output += '      IPAddress : {}'.format(os.popen("ip addr | awk '/inet / {if (++n == 2) print $2}'").read())
        output +="\n   Current Path : {}".format(os.popen('pwd').read())
        output +='===============================================================\n'

        output += '\n'
        output += 'ID ============================================================\n'
        output += os.popen('id').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'UNAME =========================================================\n'
        output += os.popen('uname -a').read()
        output += os.popen('cat /proc/cmdline').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'TTY +==========================================================\n'
        output += os.popen('who').read()
        output += os.popen('cat /proc/consoles').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'CPU ===========================================================\n'
        output += os.popen('cat /proc/cpuinfo | grep "model name" | uniq').read()
        output += os.popen(''' cat /proc/cpuinfo | awk '/cpu cores/ {gsub("cpu cores", "Cores"); print}' | uniq''').read()
        output += os.popen(''' cat /proc/cpuinfo | awk '/siblings/ {gsub("siblings", "Threads"); print}' | uniq''').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'MEMÓRIA ========================================================\n'
        output += os.popen('cat /proc/meminfo | grep MemTotal').read()
        output += os.popen('cat /proc/meminfo | grep MemFree').read()
        output += os.popen('cat /proc/meminfo | grep MemAvailable').read()
        output += os.popen('cat /proc/meminfo | grep SwapTotal').read()
        output += os.popen('cat /proc/meminfo | grep SwapFree').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'REDES =========================================================\n'
        output += os.popen('ip addr').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'NETSTAT =======================================================\n'
        output += os.popen('netstat -ano').read()
        output += '\n'
        output += os.popen('netstat -nr').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'ROTAS =========================================================\n'
        output += os.popen('cat /proc/net/route').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'SISTEMAS ======================================================\n'
        output += os.popen('df -h').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'PARTIÇÕES =====================================================\n'
        output += os.popen('lsblk -p -f -o NAME,FSTYPE,LABEL,UUID,SIZE,TYPE,TRAN,MODE').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'USB ===========================================================\n'
        output += os.popen('cat /etc/modprobe.d/blacklist.conf ').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'DISPOSITIVOS ==================================================\n'
        output += os.popen('cat /proc/devices').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'LSPCI =========================================================\n'
        output += os.popen('lspci').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'LSUSB =========================================================\n'
        output += os.popen('lsusb').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'LSLOGINS ======================================================\n'
        output += os.popen('lslogins').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'CAPTIVEF ======================================================\n'
        output += os.popen('echo Travando o programa.').read()
        #output += os.popen('getcap -r / 2>/dev/null').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'VARIAVEIS DE AMBIENTE =========================================\n'
        output += os.popen('env').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'PROCESSOS =====================================================\n'
        output += os.popen('ps axjf').read()
        output += '===============================================================\n'

        output += '\n'
        output += 'SERVIÇOS ======================================================\n'
        output += os.popen('systemctl --type=service --state=active | grep ^').read()
        output += '===============================================================\n'


        prog = input('Deseja exibir os programas instalados? (S/N) ')
        if(prog.lower() == "s"):
            output += '\n'
            output += 'PROGRAMAS INSTALADOS ===========================================\n'
            output += os.popen('dpkg --list | grep ^ii.').read()
            output += '===============================================================\n'

        output += '\n'
        output += 'BASH HISTORY===================================================\n'
        output += 'O histórico do BASH deve ser salvo manualmente por enquanto!\n'
        output += 'Use o comando: $ history\n'
        output += '===============================================================\n'

        print(output)

        sit_audi = input('Deseja salvar em arquivo? (S/N) ')
        if(sit_audi.lower() == "s"):
            os.system('rm -rf ARQ/auditoria.txt')
            with open('ARQ/auditoria.txt', 'w') as file:
                file.write(output)
            print('Seu Arquivo foi gerado com Sucesso!')
            input(press)
            main()
        else:
            input(press)
            main()
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)
    except FileNotFoundError:
        os.system(dir)
        with open('ARQ/auditoria.txt', 'w') as file:
                file.write(output)
        print('Seu Arquivo foi gerado com Sucesso!')
        input(press)
        main()


#=======================================================================================
def config():
    os.system('clear')
    ver = "v1.0-dev"
    print(f'''\033[1;33m
.d8888b.                     .d888 d8b             88888888888                888
d88P  Y88b                   d88P"  Y8P                 888                    888
888    888                   888                        888                    888
888         .d88b.  88888b.  888888 888  .d88b.         888   .d88b.   .d88b.  888
888        d88""88b 888 "88b 888    888 d88P"88b        888  d88""88b d88""88b 888
888    888 888  888 888  888 888    888 888  888        888  888  888 888  888 888
Y88b  d88P Y88..88P 888  888 888    888 Y88b 888        888  Y88..88P Y88..88P 888
 "Y8888P"   "Y88P"  888  888 888    888  "Y88888        888   "Y88P"   "Y88P"  888
                                             888
                                        Y8b d88P       \033[0;31m>Esta função precisa de Atenção!\033[m
                                         "Y88P"                            \033[7;32m{ver}\033[m''')
    print(''' MENU:

    \033[0;34m[1]\033[m - Criar usuário em RBASH
    \033[0;34m[2]\033[m - Permitir BASH padrão
    \033[0;34m[3]\033[m - Restringir TODOS os comandos
    \033[0;34m[4]\033[m - Config SSH
    \033[0;34m[5]\033[m - xxx
    \033[0;34m[6]\033[m - xxx
    \033[0;34m[7]\033[m - xxx
    \033[0;34m[8]\033[m - xxx
    \033[0;34m[9]\033[m - xxx
    \033[0;34m[10]\033[m- xxx
    ''')
    try:
        opcao=int(input('Escolha uma opção: '))

        if opcao == 1:
            user = input('Qual o usuário a ser configurado? ')
            os.system(f" useradd -m -s /bin/rbash {user}")
            senha = g.getpass("Digite a senha: ")
            os.system(f"echo '{user}:{senha}' |  chpasswd")
            os.system(f" chown root: /home/{user}/.profile")
            os.system(f" chown root: /home/{user}/.bashrc")
            os.system(f" chmod 755 /home/{user}/.profile")
            os.system(f" chmod 755 /home/{user}/.bashrc")
            print(f"Usuário '{user}' criado com sucesso, senha definida e permissões ajustadas.")
            input(press)
            main()

        elif opcao == 2:
            user = input('Qual o usuário a ser configurado? ')
            os.system(f" usermod --shell /bin/bash {user}")

        elif opcao == 3:
            if os.path.exists('/usr/share/block'):
                print("O script já foi executado anteriormente. Evitando repetição.")
                input("Pressione Enter para continuar...")
                main()
            else:
                comandos = os.popen('apropos ""').read()
                lines = comandos.splitlines()
                first_names = []

                for line in lines:
                    words = line.split()
                    if words:
                        if any(cmd in words for cmd in ["cat","ls", "cd", "exit"]):
                            continue
                        else:
                            first_names.append(words[0])

                with open('block', 'w') as block_file:
                    for name in first_names:
                        block_file.write(name + '\n')

                sita = input('Deseja confirmar o bloqueio? (S/N)')
                if sita.lower() == 's':
                    user = input('Digite o usuário: ')
                    dir = f'/home/{user}/.bashrc' ###############################
                    var = '${comandos[@]}'
                    os.system(' mv block /usr/share/block')
                    os.system(f'''echo 'comandos=($(cat /usr/share/block))' |  tee -a {dir} > /dev/null''')
                    os.system(f'''echo 'for comando in "{var}"; do' |  tee -a {dir} > /dev/null''')
                    os.system(f'''echo '  alias "$comando"="echo '\''Comando bloqueado'\''"' |  tee -a {dir} > /dev/null''')
                    os.system(f'''echo 'done' |  tee -a {dir} > /dev/null''')
                    print("Arquivo modificado com sucesso!")
                    input("Pressione Enter para continuar...")
                    main()
                else:
                    input("Pressione Enter para continuar...")
                    main()

        elif opcao == 4:
            print('''
Você deseja configurar Servidor ou Client?

\033[0;34m[1]\033[m Servidor  \033[0;34m[2]\033[m Client \033[0;34m[0]\033[m Voltar
            ''')
            sit_ssh = int(input('Escolha uma opção: '))
            if sit_ssh == 1:
                print()
            elif sit_ssh == 2:
                pass
            elif sit_ssh == 0:
                main()
            else:
                print('Digite uma opção válida!')
                input(press)

        elif opcao == 5:
            pass
        elif opcao == 6:
            pass
        elif opcao == 7:
            pass
        elif opcao == 8:
            pass
        elif opcao == 9:
            pass
        elif opcao == 10:
            pass
        elif opcao == 0:
            print(r'Volte sempre! ¯\_(ツ)_/¯')
            quit()
        elif opcao > 10:
            print('Digite uma opção válida!')
            input(press)

    except ValueError:
        print('Digite uma opção válida!')
        input(press)
    except NameError:
        print('Digite uma opção válida!')
        input(press)



    '''os.system('sudo ip addr show')
    print('\n')
    ip = input('Qual IP gostaria de atribuir a este Computador?\n')
    gateway = input('Digite o Gateway: ')
    dns = input('Digite o nameserver + ip (Ex"nameserver 8.8.8.8"):  ')
    #Definir um endereço IP estático:
    os.system(f'sudo ip addr add {ip}/24 dev eth0')
    #Configurar o gateway padrão:
    os.system(f'sudo ip route add default via {gateway}')
    #Adicionar um servidor DNS:
    os.system(f'echo "{dns}" | sudo tee /etc/resolv.conf')'''


#=======================================================================================
def linpeas():
    try:
        sit_linpeas = input('Esta opção pode demorar por muito tempo. Deseja continuar? (S/N) ')
        t.sleep(0.25)
        if(sit_linpeas.lower() == "s"):
            os.system('chmod +x linpeas.sh')
            os.system('./linpeas.sh')
        else:
            input(press)
            main()
        pass
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)


#=======================================================================================
def linenum():
    try:
        sit_linenum = input('Esta opção pode demorar por muito tempo. Deseja continuar? (S/N) ')
        t.sleep(0.25)
        if(sit_linenum.lower() == "s"):
            os.system('chmod +x LinEnum.sh')
            os.system('./LinEnum.sh')
        else:
            input(press)
            main()
        pass
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)



#=======================================================================================
####################################################################
## FUNÇÃO QUE CRIA UM CONFIGURADOR DE FIREWALL COM "firewall-cmd" ##
####################################################################
def waza():
    wversion = '\033[7;32mv2.1dev\033[m'
    
    #############################################################
    ## VERIFICA A DISTRO LINUX, INSTALA E HABILITA O FIREWALLD ##
    #############################################################
    def verifica_distro_e_firewall():
        with open("/etc/os-release", "r") as arquivo: 
            
            for linha in arquivo:
            
                if linha.startswith("ID="):
                    distro_id = linha.split("=")[1].strip().strip('"')
        
        ##############################
        ## DISTROS A SER VERIFICADA ##
        ##############################
        if distro_id in ["ubuntu", "oracle", "rhel"]:
            status = os.system(" systemctl status firewalld >/dev/null 2>&1")
        
            if status == 0:
                print("Firewalld está instalado e em execução.")
        
            else:
                intalar_firewalld = input(f"O firewalld não está instalado. Deseja instalar o firewalld no {distro_id}? (S/N): ").lower()
            
                if intalar_firewalld == "s":
                    package_manager = "apt" if distro_id == "ubuntu" else "yum"

                    #############################################
                    ## INSTALA, INICIA, E HABILITA O FIREWALLD ##
                    #############################################
                    os.system(f" {package_manager} install firewalld -y")
                    os.system(" systemctl start firewalld")
                    os.system(" systemctl enable firewalld")
                    print("Firewalld instalado e iniciado com sucesso.")
            
                else:
                    print("Firewalld não instalado. Instale manualmente e tente novamente!")
    
        else:
            print("Distribuição não suportada.")
            main()

    #######################################
    ## FUNÇÃO PARA CONFIGURAR O FIREWALL ##
    #######################################
    verifica_distro_e_firewall()

    ##############################################################
    ## DEFINE UMA SEQUENCIA DE VARIÁVEIS PARA INTERAÇÃO DO MENU ##
    ############################################################## 
    seleciona_interface = None
    seleciona_zonas_str = None
    selected_services_str = None
    block_selected_services_str = None
    selected_ports_str = None
    block_selected_ports_str = None
    port_list = None
    press = '(Pressione qualquer tecla para voltar ao menu inicial)'
    
    os.system('clear')

    try:
        while True:
            ###########################
            ## BANNER PRA FICAR COOL ##
            ###########################
            print(f'''\033[1;91m
        .DL               ;W,      ,##############Wf.     ;W,
f.     :K#L     LWL      j##,       ........jW##Wt       j##,
EW:   ;W##L   .E#f      G###,             tW##Kt        G###,
E#t  t#KE#L  ,W#;     :E####,           tW##E;        :E####,
E#t f#D.L#L t#K:     ;W#DG##,         tW##E;         ;W#DG##,
E#jG#f  L#LL#G      j###DW##,      .fW##D,          j###DW##,
E###;   L###j      G##i,,G##,    .f###D,           G##i,,G##,
E#K:    L#W;     :K#K:   L##,  .f####Gffffffff;  :K#K:   L##,
EG      LE.     ;##D.    L##, .fLLLLLLLLLLLLi   ;##D.    L##,
                                                    \033[m{wversion}''')
            
            print("Opções:\n")

            #######################################################
            ## LISTAGEM DE OPÇÕES PARA FACILITAR O USUÁRIO.      ##
            ## A LÓGICA É FAZER O USUÁRIO SELECIONAR A INTERFACE ##
            ## E A ZONA E DEPOIS PENSAR EM CONFIGURAR.           ##
            ##                                                   ##
            ## NESTE TRECHO TAMBÉM HÁ ALGUMAS CONDICIONAIS PARA  ##
            ## EXIBIR FEEDBACK DO QUE ESTÁ ACONTECENDO APOS O    ##
            ## USUÁRIO FAZER A SELEÇÃO DAS CONFIGURAÇÕES         ##
            #######################################################
            print(f"\033[0;34m[1]\033[m - Selecionar interface {'(Selecionado: ' + seleciona_interface + ')' if seleciona_interface else ''}")
        
            if seleciona_zonas_str:
                print(f"\033[0;34m[2]\033[m - Selecionar zona (Selecionado:  {seleciona_zonas_str})")
        
            else:
                print(f"\033[0;34m[2]\033[m - Selecionar zona")
        
            if selected_services_str:
                print(f"\033[0;34m[3]\033[m - Liberar serviços (Selecionados: {selected_services_str})")
        
            else:
                print("\033[0;34m[3]\033[m - Liberar serviços")            
        
            if selected_ports_str:
                print(f"\033[0;34m[4]\033[m - Liberar portas (Selecionados: {selected_ports_str})")
        
            else:
                print("\033[0;34m[4]\033[m - Liberar portas ")
        
            if block_selected_services_str:
                print(f"\033[0;34m[5]\033[m - Bloquear serviços (Selecionados: {block_selected_services_str})")
        
            else:
                print("\033[0;34m[5]\033[m - Bloquear serviços")            
        
            if block_selected_ports_str:
                print(f"\033[0;34m[6]\033[m - Bloquear portas (Selecionados: {block_selected_ports_str})")
        
            else:
                print("\033[0;34m[6]\033[m - Bloquear portas ") 
            print(f"\033[0;34m[7]\033[m - Remover interface da Zona")
            print(f"\033[0;34m[8]\033[m - Bloquear IP")
            print(f"\033[0;34m[9]\033[m - Bloquear IPs por Máscara")
            print(f'\033[0;34m[10]\033[m- Listar todas as Zonas')
            print(f"\033[0;34m[11]\033[m- Mostrar Configuração da Zona")
            print(f"\033[0;34m[12]\033[m- Listar IPs bloqueados")
            print("\033[0;34m[13]\033[m- Aplicar Configurações")
            print("\033[0;34m[0]\033[m - Sair")


            opcao = input("\nEscolha uma opção: ")

            ###########################################################
            ## EXIBE UM MENU PARA SELEÇÃO DAS INTERFACES DISPONÍVEIS ##
            ###########################################################
            if opcao == "1":
                interfaces = os.popen("ls /sys/class/net/").read().strip().split()
                print("Interfaces disponíveis:")
            
                for i, iface in enumerate(interfaces, start=1):
                    print(f"[{i}] {iface}")
            
                try:
                    print("[0] Voltar ao Menu")
                    interface_index = int(input("Escolha a interface (número): "))
                
                    if interface_index == 0:
                        seleciona_interface = None
                
                    elif 1 <= interface_index <= len(interfaces):
                        seleciona_interface = interfaces[interface_index - 1]
            
                except (ValueError, IndexError):
                    print("Escolha inválida.")

            ######################################################### 
            ## EXIBE UM MENU PARA SELEÇÃO DAS ZONAS DISPONÍVEIS    ##
            ## AQUI ELE PERMITE MULTISELEÇÃO DAS ZONAS DISPONÍVEIS ##
            #########################################################                  
            elif opcao == "2": 
                    zonas = os.popen("firewall-cmd --get-zones").read().strip().split()
                    print("Zonas disponíveis:")
                
                    for i, zone in enumerate(zonas, start=1):
                        print(f"[{i}] {zone}")
                
                    try:
                        print("[0] Voltar ao Menu")
                        seleciona_zonas = []
                    
                        while True:
                            zone_index = int(input("Escolha a zona (número): "))
                        
                            if zone_index == 0:
                                break
                        
                            elif 1 <= zone_index <= len(zonas):
                                seleciona_zona = zonas[zone_index - 1]
                                seleciona_zonas.append(seleciona_zona)  
                        
                            else:
                                print("Escolha inválida.")
                            seleciona_zonas_str = ', '.join(seleciona_zonas)
                
                    except (ValueError, IndexError):
                        print("Escolha inválida.")

            #########################################################
            ## EXIBE UM MENU PARA SELEÇÃO DOS SERVIÇOS DISPONÍVEIS ##
            ## AQUI ELE PERMITE MULTISELEÇÃO DOS SERVIÇOS          ##
            #########################################################                        
            elif opcao == "3": 
                if seleciona_zona and seleciona_interface:
                    services = os.popen("""firewall-cmd --get-services""").read().strip().split()
                    services = [service.strip() for service in services if service.strip()]
                    print("Escolha os Serviços:")
                
                    for i, service in enumerate(services, start=1):
                        print(f"[{i}] {service}")
                    try:
                        print("[0] Voltar ao Menu")
                        selected_services = []
                        
                        while True:
                            service_index = int(input("Escolha o serviço (número): "))
                        
                            if service_index == 0:
                                break
                        
                            elif 1 <= service_index <= len(services):
                                selected_service = services[service_index - 1]
                                selected_services.append(selected_service)
                            
                            else:
                                print("Escolha inválida.")
                        selected_services_str = ', '.join(selected_services)
                    
                    except (ValueError, IndexError):
                        print("Escolha inválida.")
            
                else:
                    print("Zona ou serviço não selecionado.")
        
            ###########################################################
            ## PEDE UMA ENTRADA DAS PORTAS QUE DESEJA PERMITIR.      ##
            ## AS PORTAS SÃO SEPARADAS POR "," E SENDO ENVIADAS PARA ##
            ## UMA LISTA QUE SERÁ CONFIGURADA MAIS PARA FRENTE       ##
            ###########################################################         
            elif opcao == "4":
                if seleciona_zona:
                    ports = input("Digite a(s) porta(s) desejada(s) separada(s) por vírgula: ")
                    port_list = ports.split(',')
                
                    for index, port in enumerate(port_list):
                        try:
                            port_list[index] = port.strip()
                        except ValueError:
                            print(f"Entrada inválida para a porta: {port}")
                    selected_ports_str = ', '.join(port_list)
                
                else:
                    print("Zona ou serviço não selecionado.")

            #########################################################
            ## EXIBE UM MENU PARA SELEÇÃO DOS SERVIÇOS DISPONÍVEIS ##
            ## AQUI ELE PERMITE MULTISELEÇÃO DOS SERVIÇOS          ##
            #########################################################              
            elif opcao == "5":
                if seleciona_zona:
                    block_services = os.popen("""firewall-cmd --get-services""").read().strip().split()
                    block_services = [block_service.strip() for block_service in block_services if block_service.strip()]
                    print("Escolha os Serviços:")
                
                    for i, block_service in enumerate(block_services, start=1):
                        print(f"[{i}] {block_service}")
                    try:
                        print("[0] Voltar ao Menu")
                        block_selected_services = []
                    
                        while True:
                            block_service_index = int(input("Escolha o serviço (número): "))
                        
                            if block_service_index == 0:
                                break
                        
                            elif 1 <= block_service_index <= len(block_services):
                                block_selected_service = block_services[block_service_index - 1]
                                block_selected_services.append(block_selected_service)
                        
                            else:
                                print("Escolha inválida.")
                        block_selected_services_str = ', '.join(block_selected_services)
                
                    except (ValueError, IndexError):
                        print("Escolha inválida.")
            
                else:
                    print("Zona ou serviço não selecionado.")
            
            ##############################################################
            ## A OPÇÃO 6 SERÁ O PROCESSO INVERSO DA PERMISSÃO DE PORTAS ##
            ##############################################################
            elif opcao == '6':
                pass
            
            #################################################################
            ## PERMITE REMOVER DA ZONA SELECIONADA A INTERFACE SELECIONADA ##
            #################################################################
            elif opcao == "7": 
                if seleciona_zona and seleciona_interface:
                    sit_remove = input(f"Deseja remover a interface {seleciona_interface} da zona {seleciona_zona}. (S/N) ")
                    
                    if sit_remove.lower() == 's':
                        os.system(f"firewall-cmd --zone={seleciona_zona} --permanent --remove-interface={seleciona_interface}")
                        os.system("firewall-cmd --reload")
                        print(f"Interface {seleciona_interface}removida da zona {seleciona_zona}.")
            
                else:
                    print("Selecione a Interface a ser removida e a Zona a ser configurada.")

            ############################################################################
            ## PERMITE BLOQUEAR IP INDIVIDUALMENTE, AINDA NÃO TEM TRATAMENTO COM "RE" ##
            ############################################################################        
            elif opcao == "8":
                bloquear_ip = input("Digite o IP a ser bloqueado: ")
                os.system(f"firewall-cmd --permanent --zone={seleciona_zona} --add-rich-rule='rule family=ipv4 source address={bloquear_ip} drop'")
                print(f"IP {bloquear_ip} bloqueado.")
                input(press)

            ########################################
            ##   PERMITE BLOQUEAR A FAIXA DE IP   ##
            ########################################
            elif opcao == "9":
                ip_mask = input("Digite a faixa de IP a ser bloqueado: ")
                os.system(f"firewall-cmd --permanent --zone={seleciona_zona} --add-rich-rule='rule family=ipv4 source address={ip_mask} drop'")
                print(f"Range de IPs {ip_mask} bloqueado.")
                input(press)

            ##########################
            ## LISTA TODAS AS ZONAS ##
            ##########################
            elif opcao == "10":
                os.system('firewall-cmd --list-all-zones')
                input(press)

            ##############################################
            ## LISTA A CONFIGURAÇÃO DA ZONA SELECIONADA ##
            ##############################################
            elif opcao == "11":
                try:
                    os.system(f'firewall-cmd --zone={seleciona_zona} --list-all')
                    input(press)
                except UnboundLocalError:
                    print('Selecione uma zona.')
                    input(press)
            
            #############################
            ## LISTA OS IPS BLOQUEADOS ##
            #############################
            elif opcao == "12":
                os.system(' iptables -L -n')
                input(press)

            ###############################################################################################
            ## ESTA OPÇÃO CONFIRMA AS ALTERAÇÕES SELECIONADAS, E FAZ ABRE POSSIBILIDADE DE NOVOS AJUSTES ##
            ###############################################################################################
            elif opcao == "13":
                try:
                    ########################################################
                    ## FAZ A ALTERAÇÃO DA INTERFACE PARA ZONA SELECIONADA ##
                    ########################################################
                    if seleciona_zona and seleciona_interface:
                        cfg_iface = os.popen(f"firewall-cmd --zone={seleciona_zona} --change-interface={seleciona_interface} --permanent").read()
                        print(f'Configuração da INTERFACE e ZONA: {cfg_iface}')
                        
                        ##############################################################
                        ## SE O SERVIÇO ESTIVER SELECIONADO, ELE FAZ A CONFIGURAÇÃO ##
                        ##############################################################
                        if selected_services_str != None:
                            selected_services_list = selected_services_str.split(', ')
                        
                            for service in selected_services_list:
                                cfg_service = os.popen(f"firewall-cmd --add-service={service} --permanent --zone={seleciona_zona}").read()
                                print(f'Permissão do serviço {service}: {cfg_service}')
                        
                        ############################################################
                        ## SE A PORTA ESTIVER SELECIONADA, ELE FAZ A CONFIGURAÇÃO ##
                        ############################################################
                        if selected_ports_str != None:
                            selected_ports_str = selected_ports_str.split(',')
                        
                            for port in selected_ports_str:
                                
                                if port != 0 or port != '':
                                    tcp_port = os.popen(f"firewall-cmd --add-port={port}/tcp --permanent --zone={seleciona_zona}").read()
                                    print(f'Porta {port}/tcp liberada: {tcp_port}')
                                    udp_port = os.popen(f"firewall-cmd --add-port={port}/udp --permanent --zone={seleciona_zona}").read()
                                    print(f'Porta {port}/udp liberada: {udp_port}')
                        
                        ##########################################################################
                        ## SE O BLOQUEIO DE SERVIÇO ESTIVER SELECIONADO, ELE FAZ A CONFIGURAÇÃO ##
                        ##########################################################################
                        if block_selected_services_str != None:
                            block_selected_services_list = block_selected_services_str.split(', ')
                            
                            for block_service in block_selected_services_list:
                                block_cfg_service = os.popen(f"firewall-cmd --remove-service={block_service} --permanent --zone={seleciona_zona}").read()
                                print(f'Bloqueio do serviço {block_service}: {block_cfg_service}')
                    
                        ##########################################################################
                        ## SE O BLOQUEIO DE SERVIÇO ESTIVER SELECIONADO, ELE FAZ A CONFIGURAÇÃO ##
                        ##########################################################################
                        '''
                        if block_selected_ports_str != None:
                            block_selected_ports_str = block_selected_ports_str.split(',')
                        
                            for block_port in block_selected_ports_str:
                                
                                if block_port != 0 or block_port != '':
                                    block_tcp_port = os.popen(f"firewall-cmd --remove-port={block_port}/tcp --permanent --zone={seleciona_zona}").read()
                                    print(f'Porta {block_port}/tcp bloqueada: {block_tcp_port}')
                                    block_udp_port = os.popen(f"firewall-cmd --remove-port={block_port}/udp --permanent --zone={seleciona_zona}").read()
                                    print(f'Porta {block_port}/udp bloqueada: {block_udp_port}')
                        '''
                        #########################################
                        ## ABRE O MENU DE CONFIGURAÇÕES EXTRAS ##
                        #########################################
                        try:
                            while True:
                                print("Configuração manual para a zona:")
                                print('[1] Defina o Target')
                                print("[2] Bloquear ICMP")
                                print("[3] Configurar PortForward")
                                print("[4] Configurar masquerade")
                                print("[0] Concluir")
                                choice = input("Escolha uma opção: ")
                                
                                #############################################
                                ## ABRE O MENU DE CONFIGURAÇÃO DE "TARGET" ##
                                #############################################
                                if choice == "1":
                                    print('[1] Default')
                                    print("[2] ACCEPT")
                                    print("[3] REJECT")
                                    print("[4] DROP")
                                    print("[0] Concluir")
                                    target = int(input('Escolha a opção do Target: '))
                                    
                                    if target == 1:
                                        os.system(f"firewall-cmd --zone={seleciona_zona} --set-target=default")
                                
                                    if target == 2:
                                        os.system(f"firewall-cmd --zone={seleciona_zona} --set-target=ACCEPT")
                                
                                    if target == 3:
                                        os.system(f"firewall-cmd --zone={seleciona_zona} --set-target=REJECT")  
                                
                                    if target == 4:
                                        os.system(f"firewall-cmd --zone={seleciona_zona} --set-target=DROP")
                                
                                    if target == 0:
                                        pass
                                
                                    else:
                                        print('Digite uma opção válida')

                                #################################################
                                ## ABRE O MENU DE CONFIGURAÇÃO DE "ICMP_BLOCK" ##
                                #################################################
                                if choice == "2":
                                    icmp_options = {
                                        "Echo-Request": "echo-request",
                                        "Echo-Reply": "echo-reply",
                                        "Destination Unreachable": "destination-unreachable",
                                        "Source Quench": "source-quench",
                                        "Redirect": "redirect",
                                        "Time Exceeded": "time-exceeded",
                                        "Parameter Problem": "parameter-problem",
                                        "Timestamp Request/Reply": "timestamp-request",
                                        "Address Mask Request/Reply": "address-mask-request",
                                        "Router Solicitation/Advertisement": "router-solicitation",
                                        "Traceroute": "traceroute"
                                    }
                                    print("\nOpções de bloqueio ICMP:")
                                    
                                    for num, option in enumerate(icmp_options.keys(), start=1):
                                        print(f"{num}. {option}")
                                
                                    try:
                                        option_num = int(input("Digite o número correspondente à opção de ICMP a ser bloqueada: "))
                                    
                                        if 1 <= option_num <= len(icmp_options):
                                            selected_icmp = list(icmp_options.keys())[option_num - 1]
                                            icmp_type = icmp_options[selected_icmp]
                                            os.system(f"firewall-cmd --zone={seleciona_zona} --add-icmp-block={icmp_type}")
                                            os.system("firewall-cmd --reload")
                                            print(f"Comando executado: firewall-cmd --zone={seleciona_zona} --add-icmp-block={icmp_type}")
                                            print(f"ICMP tipo '{selected_icmp}' bloqueado.")
                                    
                                        else:
                                            print("Número de opção inválido.")
                                    except ValueError:
                                        print("Entrada inválida. O número da opção deve ser um número inteiro.")
                            
                            ###############################################################################
                            ## CONFIGURA O PORTFORWARD, DIRECIONANDO O TRAFEGO DE UMA PORTA PARA A OUTRA ##
                            ###############################################################################
                                elif choice == "3":
                                    forward_sit = input("Deseja configurar o PortForward? (S/N) ")
                                    if forward_sit.lower() =='s':
                                        porta_entrada = int(input('Digite a porta de Entrada: '))
                                        porta_destino = int(input('Digite a porta de Destino: '))
                                        os.system(f"firewall-cmd --zone={seleciona_zona} --add-forward-port=port={porta_entrada}:proto=tcp:toport={porta_destino}")
                                        os.system('firewall-cmd --runtim-to-permanent')
                                        print(f"PortForward configurado ({porta_entrada} >> {porta_destino}).")
                                
                                    elif forward_sit.lower() =='n':
                                        os.system(f"firewall-cmd --zone={seleciona_zona} --remove-forward")
                                        print(f"PortForward removido.")
                                    os.system("firewall-cmd --reload")

                                elif choice == "4":
                                    masquerade_value = input("Deseja habilitar o Masquerade? (S/N) ")
                                    os.system(f"firewall-cmd --zone={seleciona_zona} --add-option=masquerade --value={masquerade_value}")
                                    os.system("firewall-cmd --reload")
                                    print(f"Comando executado: firewall-cmd --zone={seleciona_zona} --add-option=masquerade --value={masquerade_value}")
                                    print(f"Masquerade configurado para {masquerade_value}.")

                                elif choice == "0":
                                    break

                                else:
                                    print("Escolha inválida. Tente novamente.")

                        except KeyboardInterrupt:
                            print("\nPrograma encerrado.")
                            os.system('clear')
                        
                        os.system("firewall-cmd --reload")

                    else:
                        print("Zona ou serviço não selecionado.")

                except UnboundLocalError:
                    print("Zona ou serviço não selecionado.")

            elif opcao == "0":
                print("Até a próxima! (ツ)")
                break

            else:
                print("Opção inválida. Tente novamente.")
            os.system('clear')

    except KeyboardInterrupt:
        print("\nPrograma encerrado.")


#=======================================================================================
def suid():
    path = input('Digite o caminho a ser pesquisado: ')
    if (bool(path) == False):
        path = '/'
    print('Este processo pode demorar alguns segundos, aguarde ...\n')
    os.system(f'find {path} -perm -u=s -type f 2>/dev/null')
    input(press)
    main()


#=======================================================================================
def nc():
    porta = int(input('Digite a porta a ser utilizada: '))
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.bind(("", porta))
            s.listen(1)
            print(f"Escutando na porta {porta}")
            conn, addr = s.accept()
            print('Conexão recebida de',addr[0])
            while True:
                ans = conn.recv(1024).decode()
                sys.stdout.write(ans)
                command = input()
                command += "\n"
                conn.send(command.encode())
                t.sleep(0.1)
                sys.stdout.write("\033[A" + ans.split("\n")[-1])
    except OSError:
        print('Esta PORTA está sendo utilizada.')
        porta = int(input("Digite a Porta: "))
        nc(porta)
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)

def reverse_shell():
   pass


#=======================================================================================
def server_tcp():
    try:
        file = open("ARQ/output.txt", "w")
        porta = int(input("Digite a Porta a ser escutada: "))
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                s.bind(("0.0.0.0", porta))
                s.listen(5)
                print("Listening...")
                client_socket, address = s.accept()
                print(f"Received from: {address[0]}")
                data = client_socket.recv(1024).decode()
                file.write(data)
                s.close()
        except Exception as error:
            print("Erro: ", error)
            s.close()
    except FileNotFoundError:
        os.system(dir)
        server_tcp()


#=======================================================================================
def serverhttp():
    try:
        port = int(input('Qual porta será usada para o HTTP Server? '))
        server = hs.SimpleHTTPRequestHandler
        request = ss.TCPServer(("",port),server)
        print(f"Server HTTP \033[1;32m'ONLINE'\033[m na PORTA: \033[7;33m{port}\033[m\n")
        request.serve_forever()
    except OverflowError:
        print('\nDigite uma porta valida. (0 ~ 65535)')
        serverhttp()
    except ValueError:
        print('\nDigite uma porta valida. (0 ~ 65535)')
        serverhttp()
    except PermissionError:
        print('Porta sem permissão.')
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)


#=======================================================================================
def wifi_hacking():
    ################################################
    ## FUNÇÃO PARA QUEBRAR SENHA DENTRO DE UM FOR ##
    ################################################
    def magic_crack():
        try:
            #######################
            #CONVERTE PARA HASHCAT#
            #######################
            os.system('hcxpcapngtool -o WifiCrack/hash.hc22000 -E essidlist dumpfile.pcapng')

            with open('WifiCrack/hash.hc22000','r') as f:
                dump = f.read()
            
        except FileNotFoundError:
            print('\033[7;31mO arquivo "WifiCrack/*.hc22000" não foi encontrado, deixe o DUMP por mais tempo.\033[m')
            exit()

        ## implementaçao definir a forma de quebra de hash
        for hash in dump.splitlines():
            nome_hash = hash.split('*')
            
            comando1 = f"hashcat -m 22000 WifiCrack/{nome_hash[3]}.hc22000 -a 3 ?d?d?d?d?d?d?d?d | tee WifiCrack/{nome_hash[3]}.result"
            #comando1 = f"hashcat -m 22000 WifiCrack/{nome_hash[3]}.hc22000 -a 3 ?a?a?a?a?a?a?a?a --increment --increment-min=8 --increment-max=15 | tee WifiCrack/{nome_hash[3]}.result"
            #comando1 = f"hashcat -m 22000 WifiCrack/{nome_hash[3]}.hc22000 -a 0 /caminho/para/wordlist.txt | tee WifiCrack/{nome_hash[3]}.result"
#hashcat -m 22000 -a 3 ?d?d?d?d?d?d?d?d --increment --increment-min=8 --increment-max=10 -n 1024 -u 256 -w 4

            
            with open(f'WifiCrack/{nome_hash[3]}.hc22000','w') as f:
                f.write(hash)
            print()                
            print(nome_hash[3])
            print('#################################################################################################################')
            os.system(comando1)
            #os.system(comando2)
        
            #em caso de erro:
            #sudo ifconfig wlxd03745fbcadc down && sudo iwconfig wlxd03745fbcadc mode managed && sudo ifconfig wlxd03745fbcadc up
            #sudo ifconfig wlp4s0 down && sudo iwconfig wlp4s0 mode managed && sudo ifconfig wlp4s0 up

    def wifi_crack():

        ###########################
        ## VERIFICA DEPENDENCIAS ##
        ###########################
        dependencias = ["hcxdumptool", "hcxpcapngtool", "hashcat", 'xterm']

        for programa in dependencias:
            if not os.popen(f'which {programa}').read():
                os.system(f" apt install {programa}")

        interface = interfaces()

        ################################
        ## EXCLUI O CONTEUDO ANTERIOR ##
        ################################
        os.popen('rm -rf WifiCrack 2>/dev/null')
        t.sleep(1)
        os.system('mkdir WifiCrack')

        sitwifi = input('Já existe o arquivo "Wificrack/hash.hc22000"? (S/N) ')
        if sitwifi.lower() == 's':
            magic_crack()
        elif sitwifi.lower() == 'n':
            minutos = int(input('\033[7;31mQuantos minutos deseja realizar o DUMP? \033[m'))

            ################################
            ## EXCLUI O CONTEUDO ANTERIOR ##
            ################################
            os.popen('rm dumpfile* essidlist hash.hc22000 2>/dev/null')

            ####################################
            ## INTERROMPE OS SERVIÇOS DE REDE ##
            ####################################
            os.system(' systemctl stop NetworkManager.service')
            os.system(' systemctl stop wpa_supplicant.service')
            
            try:
                #####################################
                ## CAPTURA DADOS DURANTE 5 MINUTOS ##
                #####################################
                t.sleep(2)
                os.system(f'hcxdumptool -i {interface} -w dumpfile.pcapng')
            except KeyboardInterrupt:
                pass
            
            #############################################################################
            ## CASO CANCELE ANTES DO TERMINO DO PROCESSO, RESTAURA OS SERVIÇOS DE REDE ##
            #############################################################################
            if KeyboardInterrupt:
                os.system(' systemctl start NetworkManager.service')
                os.system(' systemctl start wpa_supplicant.service')

            
            ##################################
            ## RESTAURA OS SERVIÇOS DE REDE ##
            ##################################
            os.system(' systemctl start NetworkManager.service')
            os.system(' systemctl start wpa_supplicant.service')
            input('Pressione para continuar')

            magic_crack()

        else:
            print('Entrada inválida.')
            input(press)
            main()

    def wifi_scan():
        def scan(s):
            os.system('rm wash')
            os.system(f' wash -i {s} -s -a | tee wash ')
            ('')
            os.system('clear')
            with open('wash', 'r') as file:
                choose_bssid(file.read(),s)
        def deauth():
            pass
        def choose_bssid(wash_output,s):
            lines = wash_output.strip().split('\n')
            print('\nNUM   BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID')
            for i, line in enumerate(lines[2:], start=1):
                print(f"\033[0;34m[{i}]\033[m - {line}")

            selected_number = int(input("\nEscolha o número do BSSID desejado: "))

            if 1 <= selected_number <= len(lines) - 2:
                bssid = lines[selected_number + 1].split()[0]
                print(f'''\nBSSID escolhido: \033[7;33m{bssid}\033[m
    \nO que deseja fazer?

    \033[0;34m[1]\033[m - Deauth
    \033[0;34m[2]\033[m - WPSCrack
    \033[0;34m[3]\033[m - WifiHashCat
    \033[0;34m[4]\033[m - FLo0dBeacon
    \033[0;34m[5]\033[m - Em breve
    \033[0;34m[0]\033[m - Sair
    ''')
                options = {
                1: deauth,
                #2: host_discovery,
                #6: http_finder,
                #7: link,
                #8: auto_web,
                0: lambda: print(r'Volte sempre! ¯\_(ツ)_/¯') or quit
                }

                opcao = int(input('Escolha uma opção: '))
                funcao = options.get(opcao)

                if funcao:
                    funcao()
                elif opcao > 24:
                    print('Digite uma opção válida!')
                    input("Pressione Enter para continuar...")


            else:
                print("Número inválido. Tente novamente.")

        aircrack = os.popen("dpkg -l | grep aircrack | awk '{print $2}'").read()
        bully = os.popen("dpkg -l | grep bully | awk '{print $2}'").read()
        os.system(' systemctl restart NetworkManager.service')
        if "aircrack" in aircrack and "bully" in bully:
            ifaces = os.popen("ip a | grep BROADCAST | awk '{print $2}' | sed 's/://'").read()
            num = 1
            for iface in ifaces.split():
                print(f' \033[0;34m[{num}]\033[m - {iface}')
                num += 1

            sit_iface = int(input('\nEscolha uma interface para continuar: '))
            p = "'{print $2}'"
            if 1 <= sit_iface <= len(ifaces.split()):
                selected_iface = ifaces.split()[sit_iface - 1]
                sit_iface = os.popen(f"iwconfig {selected_iface} | grep Monitor ").read()
                if 'Mode:Monitor' in sit_iface:
                    scan(selected_iface)
                else:
                    print('Colocando IFACE em modo Monitor.')
                    os.popen(' airmon-ng check kill').read()
                    os.popen(f' airmon-ng start {selected_iface}')
                    t.sleep(2)
                    selected_iface = os.popen(f"ip a | grep {selected_iface} | awk {p} | sed 's/://'").read()
                    sit_iface = os.popen(f"iwconfig {selected_iface} | grep Monitor 2>/dev/null").read()
                    if 'Mode:Monitor' in sit_iface:
                        scan(selected_iface)
            else:
                print("Número inválido.")
        else:
            os.system(' apt install aircrack-ng bully -y')
    wifi_crack()
    
#################################################
## CRIA UM BANNER COM MENU DAS OPÇÕES DE TESTE ##
#################################################
def banner():
    try:
        os.system("clear")
        print(bann)
        print(''' MENU:

 \033[0;34m[1]\033[m - Host Discovery
 \033[0;34m[2]\033[m - Port Scanner
 \033[0;34m[3]\033[m - World Scanner
 \033[0;34m[4]\033[m - NC GET
 \033[0;34m[5]\033[m - WebFinder
 \033[0;34m[6]\033[m - WebCrawler (Bugs)
 \033[0;34m[7]\033[m - FormWeb
 \033[0;34m[8]\033[m - WifiHacking
 \033[0;34m[9]\033[m - BackUp
 \033[0;34m[10]\033[m- Clonar Part|Disk
 \033[0;34m[11]\033[m- CronTab
 \033[0;34m[12]\033[m- Finder
 \033[0;34m[13]\033[m- EnumLinux Auditor
 \033[0;34m[14]\033[m- Config Tool
 \033[0;34m[15]\033[m- LinPeas
 \033[0;34m[16]\033[m- LinEnum
 \033[0;34m[17]\033[m- Potemkin
 \033[0;34m[18]\033[m- Waza
 \033[0;34m[19]\033[m- SUID
 \033[0;34m[20]\033[m- NC Listen
 \033[0;34m[21]\033[m- Reverse Shell
 \033[0;34m[22]\033[m- Server TCP
 \033[0;34m[23]\033[m- ServerHTTP
 \033[0;34m[24]\033[m- Tryeres
 \033[0;34m[0]\033[m - Sair
''')
        options = {
        1: host_discovery,
        2: big_scan,
        3: world_scan,
        4: nc_get,
        5: http_finder,
        6: link,
        7: auto_web,
        8: wifi_hacking,
        9: backup,
        10: clonar,
        11: cron,
        12: finder,
        13: infosys,
        14: config,
        15: linpeas,
        16: linenum,
        #17: Potenkin,
        18: waza,
        19: suid,
        20: nc,
        21: reverse_shell,
        22: serverhttp,
        23: serverhttp,
        24: lambda: os.system('gnome-terminal --title=Python -- sudo python Tryeres/Tryeres.py') or main,
        0: lambda: print(r'Volte sempre! ¯\_(ツ)_/¯') or quit
        }

        opcao = int(input('Escolha uma opção: '))
        funcao = options.get(opcao)

        if funcao:
            funcao()

        elif opcao > 24:
            print('Digite uma opção válida!')
            input("Pressione Enter para continuar...")
            main()

    except ValueError:
        print('Digite uma opção válida!')
        input(press)
        main()

############################################
## VERIFICA SE AS BIBLIOTECAS NECESSÁRIAS ##
############################################
def vrf_requisites():
    # Verificar se o pip3 está instalado
    pip_installed = os.system('pip3 --version >/dev/null 2>&1') == 0
    print('Algumas dependências serão instaladas')
    if not pip_installed:
        print('Instalando bibliotecas necessárias')
        input('Pressione Enter para continuar...')
        print("Pip3 não está instalado. Instalando...")
        os.system('apt-get update')
        os.system('apt-get install -y python3-pip')
    else:
        print("pip3 já está instalado.")

    # Instalar bibliotecas Python se necessário
    packages = {
        'scapy': 'scapy',
        'urllib3': 'urllib3',
        'requests': 'requests',
        'beautifulsoup4': 'bs4',
        'ipaddress': 'ipaddress',
    }

    for package_name, package_module in packages.items():
        try:
            __import__(package_module)
        except ImportError:
            print(f"{package_name} não está instalado. Instalando...")
            os.system(f'pip3 install {package_module}')

    # Verificar se os pacotes foram instalados corretamente
    print("Verificando instalação dos pacotes:")
    for package_name, package_module in packages.items():
        try:
            __import__(package_module)
            print(f"    {package_name}: OK")
        except ImportError:
            print(f"    {package_name}: Falha")


    print("Instalação e verificação concluídas.")

################################
## FUNÇÃO PRINCIPAL DO CÓDIGO ##
################################
def main():

    if os.geteuid() == 0:
        try:
            banner()

        except (KeyboardInterrupt):
            print('\n'+Ctrl_C)

        except ValueError:
                print('Digite a opção correta.')
                input('(Pressione qualquer tecla para continuar)')
                main()
        except SyntaxWarning:
            pass
    else:
        print("Execute o código como ROOT.")


##############
## EXECUÇÃO ##
##############
vrf_requisites()
main()
