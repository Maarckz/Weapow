
<div align="left">
  <a href="https://github.com/maarckz/weapow" target="_blank"><img height="260" width= "960" src="https://github.com/Maarckz/Maarckz/blob/main/Images/weapow.png?raw=true"/> 
</div>


O WEAPOW é um **projeto** criado em Python, por **Maarckz**, que oferece uma coleção de ferramentas para ajudar profissionais de *segurança da informação, auditoria, e estudos para PENTEST e BUGBOUNTY* em suas tarefas diárias. Se você está procurando uma solução completa e fácil de usar, o WEAPOW pode ser exatamente o que você precisa.

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
| os | Ela permite que o código possa interagir com o sistema. |
| re | Fornece suporte para trabalhar com expressões regulares. |
| sys | Fornece acesso às variáveis e funções internas do interpretador Python. |
| socket | Permite que as aplicações possam se comunicar usando diferentes protocolos de rede |
| requests | Permite que envie requisições / solicitações HTTP. |
| time | Fornece funções para trabalhar com o tempo |
| http.server | Fornece suporte para criar servidores HTTP. |
| socketserver | Fornece uma infraestrutura para criar servidores de rede. |
| BeautifulSoup | Permite a extração de dados de arquivos HTML e XML. |
| requests.exceptions | Necessário para fazer tratamento de erros de requisição. |
| urllib | Permite manipular URL. Ex: Fazer um parse. |
| ThreadPoolExecutor | Cria Threads que podem ser usadas para executar funções em paralelo. |


## Desenvolvimento
Quer contribuir? Ótimo!
Contribuições são bem-vindas! Sinta-se à vontade.

## Funcionalidades

**1. Criar Lista de IPs:** A função `iplist()` permite ao usuário gerar uma lista de endereços IP com base nos octetos fornecidos, sendo possível escolher entre _dois_ ou _três_ primeiros octetos. Após a execução, o código produz um arquivo chamado `ips.txt` contendo a lista de IPs gerados.

> Por exemplo, se o usuário escolher 192.168 (2 octetos), a lista de IPs será gerada de 192.168.0.0 até 192.168.255.255. O arquivo resultante conterá essa série de endereços IP. O usuário é informado do sucesso da geração do arquivo, indicando os octetos fornecidos e a máscara de sub-rede utilizada. O programa aguarda a entrada do usuário antes de retornar à função principal `main()`.


**2. Host Discovery:** Esta função usa o "*ping*" para descobrir quais endereços IP estão ativos na rede. A função armazena os endereços IP ativos em um arquivo chamado `hosts.txt` . Neste script é iniciado um conjunto de threads (400 threads) para executar o **ping** para cada endereço IP.

> Para cada IP na lista, a função realiza um ping e, se bem-sucedido, adiciona o IP a um arquivo chamado `hosts.txt`. O processo de ping é paralelizado usando threads para otimizar a velocidade. O usuário é informado do progresso através da função `printer()`. Em caso de interrupção pelo usuário, o programa fornece feedback apropriado e encerra a execução. Se o usuário optar por não continuar, o programa retorna à função principal `main()`.

**3.Hostname Resolution:** A função `hostname_resolv()` lê os IPs do arquivo `hosts.txt` e exibe os hosts descobertos. Para cada IP, a função tenta resolver o nome de host correspondente usando a função `socket.gethostbyaddr()`. O resultado é impresso na tela, indicando o IP e o nome de host associado, e também é registrado no arquivo `hostname.txt`.

> A função trata exceções para situações como tempo limite de conexão,
> erros de resolução de host e interrupções do usuário. Após o processo,
> aguarda a entrada do usuário antes de retornar à função principal
> `main()`.

**4. Port Scanner:** Nesta função, o código apresenta três modos de uso para varredura de portas: único, lista e simples. Abaixo estão as descrições dos modos:

-   **Modo Único:** A função `portscan_uniq()` solicita ao usuário um endereço IP e escaneia as portas de `1 ~ 65535`. Se uma conexão for bem-sucedida, imprime a porta e o serviço associado a ela.
    
-   **Modo Lista:** Na função `portscan()`, o código lê os IPs do arquivo `hosts.txt` e exibe os hosts descobertos. Em seguida, o usuário decide se deseja prosseguir com o Port Scanner. O código verifica automaticamente os hosts ativos dentro do range de portas definido pelo usuário. Após a varredura, é gerado um arquivo `portscan.txt` contendo os hosts ativos e as portas alcançadas.
 > Este PORTSCANNER utiliza a biblioteca socket para comunicação: "`s = socket.socket(socket.AF_INET, socket.SOCK_STREAM`)"


**4. HTTP Finder :**
Esta função procura por servidores HTTP no arquivo `portscan.txt`. Ele verifica todas as linhas que contêm a *porta 80 aberta*, em seguida inicia uma conexão host, e envia uma solicitação `GET HTTP`. Ela recebe a resposta do servidor e a imprime na tela.
> Esta função ainda está em desenvolvimento, mas a intenção é manipular o conteúdo do site encontrado, e fazer solicitações específicas para cada HOST.


**5. NC GET:** A função `nc_get()` realiza a obtenção de cabeçalhos de conexão para os hosts ativos descobertos pelo Port Scanner. O código tem as seguintes características:

-   Remove arquivos antigos no diretório `ARQ/HEAD` e cria o diretório se não existir.
-   A função principal `get()` executa um comando `nc` para cada host, porta e serviço obtidos do arquivo `portscan.txt`. Os resultados são salvos em arquivos individuais no diretório `ARQ/HEAD` para cada host.
-   A função `get_parse()` lê o arquivo `portscan.txt` e extrai os detalhes de host, porta e serviço. Em seguida, inicia threads para executar a função `get()` para cada combinação de host, porta e serviço.
-   O usuário é consultado se deseja continuar com o processo. Se confirmado, os cabeçalhos das conexões são obtidos e salvos no diretório `ARQ/HEAD`. Caso contrário, o programa retorna à função principal `main()`.

> O código utiliza threads para otimizar a obtenção dos cabeçalhos, e a
> entrada do usuário é solicitada para garantir a confirmação antes de
> iniciar o processo.

**6. HTTP Finder:** A função `http_finder()` tem como objetivo identificar serviços web (HTTP/HTTPS) com base nos cabeçalhos de conexão obtidos anteriormente. Em seguida, utiliza o comando `wget` para realizar um clone praticamente perfeito do site encontrado. Algumas características principais do código são:

-   A função `wget_pg()` remove arquivos antigos, executa o comando `wget` para baixar o conteúdo da página web do host especificado na porta indicada e salva o resultado no diretório `ARQ/WEB`.
    
-   A função principal itera sobre os arquivos no diretório `ARQ/HEAD` (que contêm os cabeçalhos das conexões) e analisa cada arquivo em busca de referências a serviços web, identificando as portas associadas.
    
-   Se uma porta associada a serviços web (HTTP/HTTPS) for encontrada, é iniciada uma thread para executar a função `wget_pg()` para baixar o conteúdo da página web.
    

> O código utiliza threads para otimizar o processo, garantindo que o programa aguarde a conclusão de todas as threads antes de continuar.

    
**7. WebCrawler:** Essa função emprega **WebScraping** para extrair links de um site. Após a coleta dos links do site principal, o código imprime esses links, abrangendo tanto os principais quanto os links de diretórios secundários encontrados em cada página principal. Todos esses links são armazenados sem tratamento no arquivo `links.txt`.

> O objetivo primordial desta ferramenta é realizar um levantamento detalhado de links, identificar diretórios, mapear possíveis arquivos e revelar conteúdos sensíveis dentro de um site. A função não apenas proporciona uma visão abrangente da estrutura do site, mas também lida com exceções, como erros de conexão ou URLs inválidas, fornecendo mensagens de erro apropriadas para uma experiência de usuário mais eficiente e informativa.

**8. ServerHTTP:** Essa função inicia um servidor HTTP, solicitando ao usuário a entrada da **porta** desejada. Utilizando o módulo `http.server` do Python, o servidor é inicializado para possibilitar o envio de arquivos a partir do host específico. Essa funcionalidade pode ser empregada tanto para auditorias quanto para manutenção.

> Exemplo de Utilização: Se um servidor de arquivos estiver inoperante por algum motivo, você pode transformar qualquer computador em um servidor de arquivos temporário, facilitando o compartilhamento de arquivos para fins de diagnóstico ou recuperação.

**9. WifiScanner :**
Em breve.

**10. BackUp :**
Esta função faz backup do diretório do usuário, para uma pasta chamada `Backup`. O usuário é questionado se deseja realizar o backup ou não antes de prosseguir.
**ATENÇÃO**: *Esta função inicia após a confirmação, e ainda não foi tratada para solicitar o diretório a ser feito o backup.*
> Comando executado: `cp -v -r /home/$USER /home/$USER/Backup`

**11. Clonagem de Disco:** A função `clonar()` realiza a clonagem de um disco, permitindo a replicação de dados entre unidades de armazenamento. O código inclui uma sequência de comandos destinados a essa tarefa específica.

**12. CronTab :**
Esta função permite ao usuário configurar uma tarefa CRON. É exibida um gráfico explicando como fazer a configuração no *crontab*. 
> Esta função **substitui** a tabela do CRON, deixando somente a função atual, verifique antes, se não existe algo programado pelo `crontab -e`
> Você pode adicionar mais de uma tarefa separando as tarefas com `;`

**13. Finder :**
Esta função permite ao usuário buscar por um arquivo específico em **todo** o sistema de arquivos usando o comando `find`. Quaisquer erros durante a busca são redirecionados para `2>/dev/null`.
>Essa função pode demorar um pouco dependendo da quantidade de arquivos a serem verificados.


**14. Auditoria do Sistema:** A função `infosys()` realiza uma auditoria abrangente no sistema, coletando informações vitais em várias categorias. Os resultados são organizados em seções, incluindo ***dados do usuário, informações de sistema, detalhes da CPU, status da memória, configurações de rede, informações de dispositivos USB, detalhes de partições, programas instalados e histórico de bash.*** O relatório final é salvo no arquivo `auditoria.txt`.

**15. Config IP :**
Esta função começa mostrando as informações de rede do computador, e em seguida permite ao usuário configurar o endereço IP, gateway e servidor DNS.
>É importante notar que esta função deve ser executada com privilégios de superusuário.

**16. LinPeas :**
Esta função executa o script do Marcos Polop `LinPeas.sh`
> Essa função demora um pouco, mas é muito eficaz.

**17. LinEnum :**
Esta função executa o script do rebootuser `LinEnum.sh`
> Essa função demora um pouco, mas é muito eficaz.

**18. SUID :**
Esta função busca por arquivos com a permissão `setuid` ativada em um determinado caminho do sistema ou, caso nenhum caminho seja especificado, em todo o sistema.
>Esta função executa o comando `find` com as opções `-perm -u=s -type f`.

**19. NC Listen  :**
Esta função inicia uma "*Escuta*" na porta especificada. Quando uma conexão é estabelecida com o servidor, a função imprime o endereço IP do cliente conectado e inicia um loop para receber comandos do cliente e enviá-los de volta. 
>O nome da função, `nc`, é para fazer uma referencia ao comando **netcat***, uma ferramenta de terminal usada para enviar e receber dados em redes de computadores.

**20. Reverse Shell  :**
Esta função possui 2 funcionalidades, **Pesquisar** e **Executar**. Ela apresenta um menu ao usuário opções para executar um shell reverso em uma máquina remota. Os tipos de *shells reversos* podem ser conferidos da ferramenta, estes incluem `Bash, NC, Rust, PERL, PHP, PowerShell, Python, SoCat, Node, JavaScript, TelNet, zsh e GoLang`. O usuário seleciona uma opção e fornece o endereço IP e a porta da máquina remota à qual deseja se conectar, então gera o comando shell reverso apropriado e o executa na máquina remota.
>**Com grandes poderes vêm grandes responsabilidades** - Lee, Stan.

**21. Server TCP :**
Esta função cria um servidor TCP que ouve em uma porta informada pelo usuário e espera por uma conexão de cliente. Esta ferramenta é muito usada para estabelecer uma SHELL REVERSA sem explorar falha.
>**Com grandes poderes vêm grandes responsabilidades** - Lee, Stan.


**22. Tryeres:** 
TRYERES é uma ferramentas de teste de segurança abrangente criada para auxiliar o RECON durante um PENTEST ou BUGBOUTY. Após solicitar a URL de início, realiza diversas verificações, incluindo comandos de Whois, DNSEnum, dig, SSLScan, Nmap, WhatWeb, entre outros. Além disso, realiza um WebCrawling, identifica emails, telefones, formulários e subdomínios, fornecendo uma visão detalhada da presença online do alvo.

> O script deve ser executado como superusuário para garantir permissões
> adequadas



## License
Este projeto está licenciado sob a licença MIT.
**Free Software, Hell Yeah!**

[LinPEAS]:<https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS>
[Carlos Polop]:<https://github.com/carlospolop>
[LinEnum]:<https://github.com/rebootuser/LinEnum>
[rebootuser]:<https://github.com/rebootuser>
