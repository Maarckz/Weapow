#!/usr/bin/env python3
version = "v5dev"

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
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from statics.banner import banner
import getpass as g
from functions.interfaces import interfaces




####################################################
## GRUPO DE VARIÁVEIS QUE SÃO REPETIDAS NO CODIGO ##
####################################################
press = '\033[7;31m(Pressione qualquer tecla para voltar ao menu inicial)\033[m'
Ctrl_C = 'Você pressionou Ctrl+C para interromper o programa!'
dir = 'mkdir -p .ARQ'
SIGNALHOSTDISCOVERY = True

############################
## CRIA O DIRETÓRIO ./.ARQ ##
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
                with open('.ARQ/hosts.txt', 'a') as f:
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
    os.system('rm -f .ARQ/hosts.txt')  # Limpa o .ARQuivo anterior

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
                    with open(".ARQ/portscan.txt", "a") as f:
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
            with open(".ARQ/portscan.txt", "a") as f:
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
    os.popen('rm .ARQ/portscan.txt 2>/dev/null')
    sit_scan = input('Deseja utilizar um (H)ost ou a (L)ista? (H/L): ')

    if sit_scan.lower() == 'h':
        host = input("Digite o endereço IP ou domínio: ")
        uniq(host)
    elif sit_scan.lower() == 'l':
        with open('.ARQ/hosts.txt','r') as file:
            for line in file:
                uniq(line.strip())


#-----------------------------------------------------------------------------
###################################################################
## UM ENUMERADOR PORDEROSO DE PORTAS DE ACORDO COM O RANGE DE IP ##
###################################################################
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
def cron():
    print('''
Para configurar uma rotina C[R]ON:

\033[1;33m*  *  *  *  *  /usr/bin/python3 /caminho/do/script.*\033[m
\033[0;31m-  -  -  -  -     |                                |\033[m
\033[0;31m|  |  |  |  |     +---\033[m Caminho do Executável\033[m       \033[0;31m+---\033[m Extensão do .ARQuivo a ser Executado. Ex: .sh .c .py
\033[0;31m|  |  |  |  |
\033[0;31m|  |  |  |  +----------------------\033[m Dia da Semana (0-6) [Sendo 0 = Domingo]
\033[0;31m|  |  |  +-------------------------\033[m Mês (1-12)
\033[0;31m|  |  +----------------------------\033[m Dia do Mês (1-31)
\033[0;31m|  +-------------------------------\033[m Hora (0-23)
\033[0;31m+----------------------------------\033[m Minutos (0-59) se quiser a cada 15min use: '/15'

Exemplo:
\033[7;33m*/15 * * * * /usr/bin/python3 /caminho/do/weapow.py\033[m   [A cada 15min EXEC o .ARQuivo weapow.py usando Python3]
\033[7;33m30 15 14 6 * /tmp/backup.sh\033[m                        [No dia 14JUN às 15:30 EXEC o backup.sh]


Você pode conferir a alteração com o comando: "\033[0;34m$ crontab -e\033[m"

''')
    sit_cron = input("Deseja substituir as configurações do C[R]ON? (S/N)\n")
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
def config():
    #############################################
    ## Função para exibir o cabeçalho ##
    #############################################
    def display_header(ver):
        print(f'''\033[1;33m

\033[0;31m>Esta função precisa de Atenção!\033[m
''')

    #############################################
    ## Função para exibir o menu ##
    #############################################
    def display_menu():
        print('''
MENU:
              
\033[0;34m[1]\033[m - Criar usuário em RBASH
\033[0;34m[3]\033[m - Restringir TODOS os comandos
\033[0;34m[5]\033[m - Configurar IP
\033[0;34m[6]\033[m - Remove KeySensitive
\033[0;34m[0]\033[m - Sair
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
            print(".ARQuivo modificado com sucesso!")


    #############################################
    ## Função para configurar IP ##
    #############################################
    def configure_ip():
        print("Configuração de IP:")
        
        
        # Definir interface de rede (substitua 'eth0' ou 'enp0s3' com a interface correta)
        interface = interfaces()
        
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
        os.system(f'ip link set {interface} down')
        os.system(f'ip link set {interface} up')
        print("Configuração de IP aplicada com sucesso!")


    #############################################
    ## Remove o KeySensitive do Terminal ##
    #############################################
    def remove_keysensitive():
        os.system('echo set completion-ignore-case on | sudo tee -a /etc/inputrc')


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
            block_commands()
        elif opcao == 3:
            configure_ip()
        elif opcao == 4:
            remove_keysensitive()
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
#################################################
## CRIA UM BANNER COM MENU DAS OPÇÕES DE TESTE ##
#################################################
def bann():
    try:
        os.system("clear")
        banner(version)
        print(''' MENU:

 \033[0;34m[1]\033[m - Host Discovery
 \033[0;34m[2]\033[m - Port Scanner
 \033[0;34m[3]\033[m - World Scanner
 \033[0;34m[4]\033[m - CronTab
 \033[0;34m[5]\033[m - Config. Linux
 \033[0;34m[0]\033[m - Sair
''')
        options = {
        1: host_discovery,
        2: big_scan,
        3: world_scan,
        4: cron,
        5: config,
        0: lambda: print(r'Volte sempre! ¯\_(ツ)_/¯') or quit
        }

        opcao = int(input('Escolha uma opção: '))
        funcao = options.get(opcao)

        if funcao:
            funcao()

        elif opcao > 23:
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
        bann()

    except (KeyboardInterrupt):
        print('\n'+Ctrl_C)

    except ValueError:
            print('Digite a opção correta.')
            input(press)
            main()
    except SyntaxWarning:
        pass


#-----------------------------------------------------------------------------
main()

