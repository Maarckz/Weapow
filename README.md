

<div align="left">
  <a href="https://github.com/maarckz/weapow" target="_blank"><img height="260" width= "950" src="https://github.com/Maarckz/Maarckz/blob/main/Images/weapow.png?raw=true"/> 
</div>


O WEAPOW é um **projeto** criado em Python, por Maarckz (SH1N003), que oferece uma coleção de ferramentas para ajudar profissionais de *segurança da informação, auditoria, e estudos para PENTEST e BUGBOUNTY* em suas tarefas diárias. Se você está procurando uma solução completa e fácil de usar, o WEAPOW pode ser exatamente o que você precisa.

Algumas das principais funções incluem a criação de ListIP, HostDiscovery, PortScanner, Search HTTP, Server HTTP, BackUP, Configuração CRON e busca por vulnerabilidades específicas em todo o sistema de arquivos. O projeto WEAPOW é um script para facilitar a vida de profissionais de segurança da informação e entusiastas que desejam aprender mais sobre essa área. Com uma gama de recursos e ferramentas, o WEAPOW pode ajudá-lo a proteger sua rede, obter mais  informações sobre ela.

## Instalação

Esta ferramente exige Python3+
```sh
sudo apt-get install python3
```
Baixa bastar e executar:

```sh
git clone https://github.com/Maarckz/Weapow.git && cd Weapow && python weapow.py
```

## Bibliotecas

| Biblioteca | Função |
| ------ | ------ |
| random | Fornece ferramentas para trabalhar com valores aleatórios. |
| ThreadPoolExecutor | Cria Threads que podem ser usadas para executar funções em paralelo. |
| socket | Permite que as aplicações possam se comunicar usando diferentes protocolos de rede |
| os | Ela permite que o código possa interagir com o sistema. |
| sys | Fornece acesso às variáveis e funções internas do interpretador Python. |
| time | Fornece funções para trabalhar com o tempo |
| re | Fornece suporte para trabalhar com expressões regulares. |
| http.server | fornece suporte para criar servidores HTTP. |
| socketserver | fornece uma infraestrutura para criar servidores de rede. |

## Desenvolvimento
Quer contribuir? Ótimo!
Contribuições são bem-vindas! Sinta-se à vontade.

## Funcionalidades

 **1. Criar lista de IPs:**
Esta função cria uma lista de endereços IP com base nos *dois* ou *três* primeiros octetos fornecidos pelo usuário. Ao final do processo, será gerado um arquivo `ips.txt` com os IPs.
> Você digitou 192.168 (2 octetos), será gerado uma lista de IP de 192.168.0.0 até 192.168.255.255. 


 **2. Host Discovery :**
Esta função usa o "*ping*" para descobrir quais endereços IP estão ativos na rede. A função armazena os endereços IP ativos em um arquivo chamado `hosts.txt` . Neste script é iniciado um conjunto de threads (400 threads) para executar o **ping** para cada endereço IP.
> Na opção de confirmação, ao digitar "simple", você poderá ver o comando sem usar threads.


 **3. Port Scanner  :**
Nesta função, existem 3 modos de uso. Você pode fazer em um IP específico, em uma lista `hosts.txt` ou o modo "*simple*" como no caso anterior.
 - **Modo Único**: O script solicita um endereço IP para escanear e verifica as portas de `1 ~ 65535`.  Se a conexão for bem-sucedida, o script imprime a porta e o serviço associado a ela. 
 - **Modo Lista**: Aqui você pode usar a versão "*simple*" mencionada anteriormente, mas prosseguindo normalmente o script, verifica automaticamente os HostsUP do arquivo `hosts.txt`, dentro do Range de portas definido pelo usuário. Logo após o PortScan, é gerado um arquivo`portscan.txt` contendo os HostsUP + as portas que a ferramenta conseguiu se comunicar.
> Este PORTSCANNER utiliza a biblioteca socket para fazer comunicação:
    "s  =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)"

**4. HTTP Finder :**
Esta função procura por servidores HTTP no arquivo `portscan.txt`. Ele verifica todas as linhas que contêm a *porta 80 aberta*, em seguida inicia uma conexão host, e envia uma solicitação `GET HTTP`. Ela recebe a resposta do servidor e a imprime na tela.
> Esta função ainda está em desenvolvimento, mas a intenção é manipular o conteúdo do site encontrado, e fazer solicitações específicas para cada HOST.

**5. ServerHTTP :**
Esta é uma função que inicia um servidor HTTP. Ele recebe uma entrada do usuário para especificar qual **porta** deve ser usada para o servidor e, em seguida, inicia o servidor usando o módulo `http.server` do Python.
> Essa função pode ser usada para envio de arquivos de um determinado host, tanto para uma auditoria, como para manutenção. 
> Ex: Servidor de arquivos está fora (por algum motivo), você consegue fazer de um PC qualquer um servidor de arquivos.

**6. BackUp :**
Esta função faz backup do diretório do usuário, para uma pasta chamada `Backup`. O usuário é questionado se deseja realizar o backup ou não antes de prosseguir.
**ATENÇÃO**: *Esta função inicia após a confirmação, e ainda não foi tratada para solicitar o diretório a ser feito o backup.*
> Comando executado: `cp -v -r /home/$USER /home/$USER/Backup`

**7. CronTab :**
Esta função permite ao usuário configurar uma tarefa CRON. É exibida um gráfico explicando como fazer a configuração no *crontab*. 
> Esta função **substitui** a tabela do CRON, deixando somente a função atual, verifique antes, se não existe algo programado pelo `crontab -e`
> Você pode adicionar mais de uma tarefa separando as tarefas com `;`

**8. Finder :**
Esta função permite ao usuário buscar por um arquivo específico em **todo** o sistema de arquivos usando o comando `find`. Quaisquer erros durante a busca são redirecionados para `2>/dev/null`.
>Essa função pode demorar um pouco dependendo da quantidade de arquivos a serem verificados.

**9. Auditor :**
Esta função coleta informações do sistema, onde são organizadas em seções para diferentes tipos de informações, incluindo: ***usuário, sistema, CPU, memória, rede, partições, dispositivos USB, programas instalados e histórico de bash***, em seguida as salva em no arquivo `auditoria.txt`
> Essa função pode não funcionar dependendo da Distro usada.

**10. Config IP :**
Esta função começa mostrando as informações de rede do computador, e em seguida permite ao usuário configurar o endereço IP, gateway e servidor DNS.
>É importante notar que esta função deve ser executada com privilégios de superusuário.

**11. LinPeas :**
Esta função executa o script do Marcos Polop `LinPeas.sh`
> Essa função demora um pouco, mas é muito eficaz.

**12. LinEnum :**
Esta função executa o script do rebootuser `LinEnum.sh`
> Essa função demora um pouco, mas é muito eficaz.

**13. SUID :**
Esta função busca por arquivos com a permissão `setuid` ativada em um determinado caminho do sistema ou, caso nenhum caminho seja especificado, em todo o sistema.
>Esta função executa o comando `find` com as opções `-perm -u=s -type f`.

**14. NC Lister  :**
Esta função inicia uma "*Escuta*" na porta especificada. Quando uma conexão é estabelecida com o servidor, a função imprime o endereço IP do cliente conectado e inicia um loop para receber comandos do cliente e enviá-los de volta. 
>O nome da função, `nc`, é uma abreviação de `netcat`, uma ferramenta de terminal usada para enviar e receber dados em redes de computadores.

**15. Reverse Shell  :**
Esta função possui 2 funcionalidades, **Pesquisar** e **Executar**. Ela apresenta um menu ao usuário opções para executar um shell reverso em uma máquina remota. Os tipos de *shells reversos* podem ser conferidos da ferramenta, estes incluem `Bash, NC, Rust, PERL, PHP, PowerShell, Python, SoCat, Node, JavaScript, TelNet, zsh e GoLang`. O usuário seleciona uma opção e fornece o endereço IP e a porta da máquina remota à qual deseja se conectar, então gera o comando shell reverso apropriado e o executa na máquina remota.
>**Com grandes poderes vêm grandes responsabilidades** - Lee, Stan.

**16. Server TCP :**
Esta função cria um servidor TCP que ouve em uma porta informada pelo usuário e espera por uma conexão de cliente. Esta ferramenta é muito usada para estabelecer uma SHELL REVERSA sem explorar falha.
>**Com grandes poderes vêm grandes responsabilidades** - Lee, Stan.

## License
Este projeto está licenciado sob a licença MIT.
**Free Software, Hell Yeah!**

[LinPEAS]:<https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS>
[Carlos Polop]:<https://github.com/carlospolop>
[LinEnum]:<https://github.com/rebootuser/LinEnum>
[rebootuser]:<https://github.com/rebootuser>


