
# **WEAPOW**

Este **projeto** é uma coleção de ferramentas para auxiliar em tarefas de *segurança da informação, auditoria, e estudos para PENTEST e BUGBOUNTY*.

## Instalação

Esta ferramente exige Python3+
```sh
sudo apt-get install python3
```
Baixa bastar e executar:

```sh
git clone https://github.com/Maarckz/Weapow.git
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
Esta função permite ao usuário buscar por um arquivo específico em **todo** o sistema de arquivos usando o comando `find`. Quaisquer erros durante a busca são redirecionados para `2>/dev/null`.
>Essa função pode demorar um pouco dependendo da quantidade de arquivos a serem verificados.

**14. NC Lister  :**
Esta função permite ao usuário buscar por um arquivo específico em **todo** o sistema de arquivos usando o comando `find`. Quaisquer erros durante a busca são redirecionados para `2>/dev/null`.
>Essa função pode demorar um pouco dependendo da quantidade de arquivos a serem verificados.

**15. Reverse Shell  :**
Esta função permite ao usuário buscar por um arquivo específico em **todo** o sistema de arquivos usando o comando `find`. Quaisquer erros durante a busca são redirecionados para `2>/dev/null`.
>Essa função pode demorar um pouco dependendo da quantidade de arquivos a serem verificados.

**16. Server TCP :**
Esta função permite ao usuário buscar por um arquivo específico em **todo** o sistema de arquivos usando o comando `find`. Quaisquer erros durante a busca são redirecionados para `2>/dev/null`.
>Essa função pode demorar um pouco dependendo da quantidade de arquivos a serem verificados.

## License
Este projeto está licenciado sob a licença MIT.
**Free Software, Hell Yeah!**

[LinPEAS]:<https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS>
[Carlos Polop]:<https://github.com/carlospolop>
[LinEnum]:<https://github.com/rebootuser/LinEnum>
[rebootuser]:<https://github.com/rebootuser>


