
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





 8. [7] - CronTab 
 9. [8] - Finder 
 10. [9] - Auditor 
 11. [10]- Config IP 
 12. [11]- LinPeas 
 13. [12]- LinEnum 
 14. [13]- SUID 
 15. [14]- NC Lister 
 16. [15]- Reverse Shell 
 17. [16]- Server TCP

## License
Este projeto está licenciado sob a licença MIT.
**Free Software, Hell Yeah!**

[LinPEAS]:<https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS>
[Carlos Polop]:<https://github.com/carlospolop>
[LinEnum]:<https://github.com/rebootuser/LinEnum>
[rebootuser]:<https://github.com/rebootuser>


