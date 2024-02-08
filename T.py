import os 
dados =[]

hostname = os.popen("hostname").read()
user = os.popen("whoami").read()
IP = os.popen("ip addr show | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1").read()
MAC= os.popen("ip link show | grep 'link/ether' | awk '{print $2}'").read()


print('ID DA ET:\n',hostname)
print('NIP:\n',user)
print('IPs:\n',IP)
print('MACs:\n',MAC)


# Definindo uma lista vazia para armazenar os dados
$dados = @()

# Obtendo o hostname
$hostname = hostname

# Obtendo o nome do usuário
$user = whoami

# Obtendo o endereço IP
$IP = (ip addr show | Select-String -Pattern 'inet ' | ForEach-Object { $_ -split ' ' })[1].Split('/')[0]

# Obtendo o endereço MAC
$MAC = (ip link show | Select-String -Pattern 'link/ether' | ForEach-Object { $_ -split ' ' })[1]

# Adicionando os dados à lista
$dados += "ID DA ET:`n$hostname"
$dados += "NIP:`n$user"
$dados += "IPs:`n$IP"
$dados += "MACs:`n$MAC"

# Exibindo os dados
Write-Output $dados
