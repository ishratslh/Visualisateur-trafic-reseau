#code source
from pathlib import Path

global trames
global numero #numéro de trame à choisir
header_length = 5 #donc pas d'options donc TCP direct
ipSource = ""
ipDest = ""
ty_pe = ""#type

#var dans le cas d'un protocole TCP
portS = ""
portD = ""
protocol = ""
seq = ""
ack = ""
window = ""

#var dans le cas d'un protocole HTTP
requeteHTTP=""

def analyse_trame(numero, trames) :
    global ipSource
    global ipDest
    global protocol
    global ty_pe
    global portS
    global portD
    global seq
    global ack
    global window
    global flags
    global requeteHTTP
    global tailleOpt
    ipSource = addIPSource(numero, trames)
    ipDest = addIPDest(numero, trames)
    #print("ip src =", ipSource)
    #print("ip dest =", ipDest)
    ty_pe = getType(numero, trames)
    #print("type =", ty_pe)
    protocol = getProtocol(numero, trames)
    #print("protocol =", protocol)
    if (protocol == "TCP") :
        portS = tcp_portS(numero, trames)
        portD = tcp_portD(numero, trames)
        #print("port source =", portS)
        #print("port dest =", portD)
        seq = getSEQ(numero, trames)
        ack = getACK(numero, trames)
        window = getWindow(numero, trames)
        #print("seq =", seq)
        #print("ack =", ack)
        #print("window =", window)
        tailleOptions = tailleOpt(numero, trames)
        flags = tcp_flags(numero, trames)
    if (protocol== "HTTP") :
        tailleOptions = tailleOpt(numero, trames)
        portD = tcp_portS(numero, trames)
        portS = tcp_portD(numero, trames)
        requeteHTTP=getRequete(numero, trames)
    else :
        protocol == "pas un protocol TCP"

def list_trame(trames):
    with open(trames, 'r') as file :
        txt = Path(trames).read_text()
        offset0='0000   '
        listTrames =[ offset0+trame for trame in txt.split(offset0, -1) if trame] #isolation de la trame souhaitée
        file.close()
    return listTrames

def select_trame(trames, numero):
    """with open(trames, 'r') as file :
        txt = Path(trames).read_text()
        offset0='0000   '
        listTrames =[ offset0+trame for trame in txt.split(offset0, -1) if trame] #isolation de la trame souhaitée
        file.close()"""
    res = ""
    liste = list_trame(trames)
    if (numero<len(liste)):
        str=liste[numero] #list->str
        #print (str)
        res = str.split() #enlevons les espaces
        #for i in res :
            #print(i)
    else:
        exit
    return res

def addIPSource(numero, trames):
    #colonne = 12
    #ligne = 2
    trame = select_trame(trames, numero)
    ip = str( int( trame[28], 16) )+ "." + str( int( trame[29], 16) ) + "." + str( int( trame[30], 16) )+ "." + str( int( trame[31], 16) )
    #print("IP Source = ", ip)
    ipSource = ip
    return ip

def addIPDest(numero, trames):
    #colonne = 16, 17, 2, 3
    #ligne = 2, 3
    trame = select_trame(trames, numero)
    ip = str( int( trame[32], 16) )+ "." + str( int( trame[33], 16) ) + "." + str( int( trame[35], 16) )+ "." + str( int( trame[36], 16) )
    #print("IP Destination = ", ip)
    return ip

def getProtocol(numero, trames) :
    trame = select_trame(trames, numero)
    if trame[25] == "06" :
        if (getHTTP(numero, trames)=="HTTP") :
            return "HTTP"
        #elif 
        else :
            return "TCP"
    if trame[25] == "01" : return "ICMP"
    if trame[25] == "11" : return "UDP"
    if trame[13]+trame[14] == "0806" : return "ARP"

    #print(protocol)

def tcp_portS(numero, trames) :
    trame = select_trame(trames, numero)
    res = str( int(trame[37]+trame[38], 16) )
    #print(res)
    return res

def tcp_portD(numero, trames) :
    trame = select_trame(trames, numero)
    res = str( int(trame[39]+trame[40], 16) )
    #print(res)
    return res

def getSEQ(numero, trames) :
    trame = select_trame(trames, numero)
    res = str( int(trame[41]+trame[42]+trame[43]+trame[44], 16) )
    return res

def getACK(numero, trames) :
    trame = select_trame(trames, numero)
    res = str( int(trame[45]+trame[46]+trame[47]+trame[48], 16) )
    return res

def getWindow(numero, trames) :
    trame = select_trame(trames, numero)
    res = str( int(trame[52]+trame[53], 16) )
    return res

def thl_tcp(numero, trames):
    #Si thl>5, il y a des options
    trame = select_trame(trames, numero)
    res = (int(trame[49], 16))/10
    return res

def tcp_flags(numero, trames) :
    trame = select_trame(trames, numero)
    res=""
    if (trame[49][1]+trame[50]=="002") :
        res = "  [SYN]  "
    if (trame[49][1]+trame[50]=="010") :
        res = "  [ACK]  "
    if (trame[49][1]+trame[50]=="012") :
        res = "[SYN,ACK]"
    if (trame[49][1]+trame[50]=="014") :
        res = "[RST,ACK]"
    if (trame[49][1]+trame[50]=="011") :
        res = "[FIN,ACK]"
    if (trame[51][1]+trame[52]=="020") :
        res = "[URG]"
    if (trame[49][1]+trame[50]=="008") :
        res = "  [PSH]  "
    if (trame[49][1]+trame[50]=="018") :
        res = "[PSH,ACK]"
    if (trame[49][1]+trame[50]=="019") :
        res = "[FIN,PSH,ACK]"

    return res

def getType(numero, trames):
    trame = select_trame(trames, numero)
    if (trame[13]+trame[14] == "0800") :
        if ( trame[15][0] == "4" ) :
             res = "IPv4"
             return res
        if ( trame[15][0] == "6" ) :
             res = "IPv6"
             return res

def getHTTP(numero, trames):
    trame = select_trame(trames, numero)
    if (tcp_portD(numero, trames) == 80 or tcp_portS(numero, trames) ==80):
            return "HTTP"
    for i in range(0, len(trame)-3 ) :
        if (trame[i]+trame[i+1]+trame[i+2]+trame[i+3] == "0d0a0d0a") :
            #print(trame[i]+trame[i+1]+trame[i+2]+trame[i+3] )
            return "HTTP"
        

def getRequete(numero, trames):
    #supposons qu'on est déjà dans une trame http
    res = ""
    tO=tailleOpt(numero, trames)
    trame = select_trame(trames, numero)
    if (tO==0):
        for i in range(58, len(trame)-1 ) :
            if (trame[i]+trame[i+1] == "0d0a") :
                break
            elif (len(trame[i])>2) :
                res+=""
            else:
                res+=trame[i]
        #print(res)
    else :
         for i in range(58+tO+1, len(trame)-1 ) :
             if (trame[i]+trame[i+1] == "0d0a") :
                 break
             elif (len(trame[i])>2) :
                 res+=""
             else:
                 res+=trame[i]

    byte_array = bytearray.fromhex(res)
    return byte_array.decode()
    #return res.decode("hex")

def tailleOpt(numero, trames):
    trame = select_trame(trames, numero)
    thl = int(trame[49][0], 16)
    if (thl>5) :
        res = (thl*4)-20
        return res
    else:
        return 0


#list_trame(trames)
#select_trame(trames, 2)
#analyse_trame(numero)


