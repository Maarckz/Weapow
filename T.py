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
