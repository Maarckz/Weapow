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
