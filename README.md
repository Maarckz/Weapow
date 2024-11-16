


<div align="left">
  <a href="https://github.com/maarckz/weapow" target="_blank"><img height="260" width= "960" src="https://github.com/Maarckz/Maarckz/blob/main/Images/weapow.png?raw=true"/> 
</div>


O WEAPOW é um **projeto** criado em Python,  que oferece uma coleção de ferramentas para ajudar profissionais de *segurança da informação, auditoria, e estudos para PENTEST e BUGBOUNTY* em suas tarefas diárias. Se você está procurando uma solução completa e fácil de usar, o WEAPOW pode ser exatamente o que você precisa. Ela inclui funções de descoberta de hosts, scanners de portas, ataques de força bruta em redes Wi-Fi, configuração de firewalls e muito mais.


## Instalação

Esta ferramente exige Python3+
```sh
sudo apt-get install python3
```
Baixa bastar e executar:

```sh
git clone https://github.com/Maarckz/Weapow.git && cd Weapow && sudo python3 Weapow.py
```

## Desenvolvimento
Quer contribuir? Ótimo!
Contribuições são bem-vindas! Sinta-se à vontade.

## Bibliotecas

| Biblioteca | Função |
| ------ | ------ |
| os | Ela permite que o código possa interagir com o sistema. |
| re | Fornece suporte para trabalhar com expressões regulares. |
| sys | Fornece acesso às variáveis e funções internas do interpretador Python. |
| time | Fornece funções para trabalhar com o tempo |
| tqdm | Barra de progresso. |
| queue | Estrutura de dados para filas. |
| signal | Manipulação de sinais, como interrupções do sistema. |
| socket | Permite que as aplicações possam se comunicar usando diferentes protocolos de rede |
| requests | Permite que envie requisições / solicitações HTTP. |
| getpass | Fornece uma maneira de lidar com a entrada de senha do usuário de forma mais segura. |
| http.server | Fornece suporte para criar servidores HTTP. |
| socketserver | Fornece uma infraestrutura para criar servidores de rede. |
| BeautifulSoup | Permite a extração de dados de arquivos HTML e XML. |
| requests.exceptions | Necessário para fazer tratamento de erros de requisição. |
| ipaddress | Manipulação de endereços IP. |
| multiprocessing | Processamento paralelo em múltiplos núcleos. |
| urllib | Permite manipular URL. Ex: Fazer um parse. |
| ThreadPoolExecutor | Cria Threads que podem ser usadas para executar funções em paralelo. |


## Funcionalidades




**1. Host Discovery:** Esta função usa o "*ping*" para descobrir quais endereços IP estão ativos na rede. A função armazena os endereços IP ativos em um arquivo chamado `hosts.txt` . Neste script é iniciado um conjunto de threads (160 threads) para executar o **ping** para cada endereço IP.

> Para cada IP na lista, a função realiza um ping e, se bem-sucedido, adiciona o IP a um arquivo chamado `hosts.txt`. O processo de ping é paralelizado usando threads para otimizar a velocidade. 

**1.1.Hostname Resolution:** A função `hostname_resolv()` lê os IPs do arquivo `hosts.txt` e exibe os hosts descobertos. Para cada IP, a função tenta resolver o nome de host correspondente usando a função `socket.gethostbyaddr()`. O resultado é impresso na tela, indicando o IP e o nome de host associado, e também é registrado no arquivo `hostname.txt`.

> A função trata exceções para situações como tempo limite de conexão,
> erros de resolução de host e interrupções do usuário. Após o processo,
> aguarda a entrada do usuário antes de retornar à função principal
> `main()`.

**2. Port Scanner:** Nesta função, o código apresenta três modos de uso para varredura de portas: único, lista e simples. Abaixo estão as descrições dos modos:

-   **Modo Único:** A função `portscan_uniq()` solicita ao usuário um endereço IP e escaneia as portas de `1 ~ 65535`. Se uma conexão for bem-sucedida, imprime a porta e o serviço associado a ela.
    
-   **Modo Lista:** Na função `portscan()`, o código lê os IPs do arquivo `hosts.txt` e exibe os hosts descobertos. Em seguida, o usuário decide se deseja prosseguir com o Port Scanner. O código verifica automaticamente os hosts ativos dentro do range de portas definido pelo usuário. Após a varredura, é gerado um arquivo `portscan.txt` contendo os hosts ativos e as portas alcançadas.
 > Este PORTSCANNER utiliza a biblioteca socket para comunicação: "`s = socket.socket(socket.AF_INET, socket.SOCK_STREAM`)"


**3. BannerGrab (Em desenvolvimento):** A função `nc_get()` realiza a obtenção de cabeçalhos de conexão para os hosts ativos descobertos pelo Port Scanner. O código tem as seguintes características:

-   Remove arquivos antigos no diretório `ARQ/HEAD` e cria o diretório se não existir.
-   A função principal `get()` executa um comando `nc` para cada host, porta e serviço obtidos do arquivo `portscan.txt`. Os resultados são salvos em arquivos individuais no diretório `ARQ/HEAD` para cada host.
-   A função `get_parse()` lê o arquivo `portscan.txt` e extrai os detalhes de host, porta e serviço. Em seguida, inicia threads para executar a função `get()` para cada combinação de host, porta e serviço.
-   O usuário é consultado se deseja continuar com o processo. Se confirmado, os cabeçalhos das conexões são obtidos e salvos no diretório `ARQ/HEAD`. Caso contrário, o programa retorna à função principal `main()`.

> O código utiliza threads para otimizar a obtenção dos cabeçalhos, e a
> entrada do usuário é solicitada para garantir a confirmação antes de
> iniciar o processo.

**6. Web Discovery + Subdomain:** Descrição em desenvolvimento.
-   Basicamente a função ira usar um PATH de Wordlist para fazer enumeração.
> O código utiliza threads para otimizar o processo, garantindo que o programa aguarde a conclusão de todas as threads antes de continuar.

    
**7. WebCrawler:** Essa função emprega **WebScraping** para extrair links de um site. Após a coleta dos links do site principal, o código imprime esses links, abrangendo tanto os principais quanto os links de diretórios secundários encontrados em cada página principal. Todos esses links são armazenados sem tratamento no arquivo `links.txt`.

> O objetivo primordial desta ferramenta é realizar um levantamento detalhado de links, identificar diretórios, mapear possíveis arquivos e revelar conteúdos sensíveis dentro de um site. A função não apenas proporciona uma visão abrangente da estrutura do site, mas também lida com exceções, como erros de conexão ou URLs inválidas, fornecendo mensagens de erro apropriadas para uma experiência de usuário mais eficiente e informativa.


**O Resto da descrição será atualizada em breve**


## License
Este projeto está licenciado sob a licença MIT.
**Free Software, Hell Yeah!**

[LinPEAS]:<https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS>
[Carlos Polop]:<https://github.com/carlospolop>
[LinEnum]:<https://github.com/rebootuser/LinEnum>
[rebootuser]:<https://github.com/rebootuser>

