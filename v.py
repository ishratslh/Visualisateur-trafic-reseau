#code source
from pathlib import Path

trames = 'trace3.txt'
numero = 6 #numéro de trame à choisir

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
tailleOptions=0

#var dans le cas d'un protocole HTTP
http = ""
requete=""

def analyse_trame() :
    ipSource = addIPSource()
    ipDest = addIPDest()
    print("ip src = ", ipSource)
    print("ip dest = ", ipDest)

    ty_pe = getType()
    print("type = ", ty_pe)

    protocol = getProtocol()
    print("protocol = ", protocol)
    if (protocol == "TCP") :
        portS = tcp_portS()
        portD = tcp_portD()
        print("port source = ", portS)
        print("port dest = ", portD)
        seq = getSEQ()
        ack = getACK()
        window = getWindow()
        print("seq =", seq)
        print("ack =", ack)
        print("window = ", window)
        tailleOptions = tailleOpt()
        print(tailleOptions)
    if (protocol== "HTTP") :
        http = getHTTP()
        print("http = ",http)
        requete=getRequete()
        print("requete = ", requete)

def select_trame(trames, numero):
    with open(trames, 'r') as file :
        txt = Path(trames).read_text()
        listTrames = txt.split('\n\n', -1) #isolation de la trame souhaitée
        file.close()
        str=''.join(listTrames[numero]) #list->str
        #print (str)
        res = str.split() #enlevons les espaces
        #for i in res :
            #print(i)
        return res

def addIPSource():
    #colonne = 12
    #ligne = 2
    trame = select_trame(trames, numero)
    ip = str( int( trame[28], 16) )+ "." + str( int( trame[29], 16) ) + "." + str( int( trame[30], 16) )+ "." + str( int( trame[31], 16) )
    #print("IP Source = ", ip)
    return ip

def addIPDest():
    #colonne = 16, 17, 2, 3
    #ligne = 2, 3
    trame = select_trame(trames, numero)
    ip = str( int( trame[32], 16) )+ "." + str( int( trame[33], 16) ) + "." + str( int( trame[35], 16) )+ "." + str( int( trame[36], 16) )
    #print("IP Destination = ", ip)
    return ip

def getProtocol() :
    trame = select_trame(trames, numero)
    if trame[25] == "06" :
        if (getHTTP()=="HTTP") :
            return "HTTP"
        else :
            return "TCP"
    if trame[25] == "01" : return "ICMP"
    if trame[25] == "11" : return "UDP"
    #print(protocol)

def tcp_portS() :
    trame = select_trame(trames, numero)
    print(trame[37])
    print(trame[38])
    res = str( int(trame[37]+trame[38], 16) )
    print(res)
    return res

def tcp_portD() :
    trame = select_trame(trames, numero)
    res = str( int(trame[39]+trame[40], 16) )
    print(res)
    return res

def getSEQ() :
    trame = select_trame(trames, numero)
    res = str( int(trame[42]+trame[43]+trame[44]+trame[45], 16) )
    return res

def getACK() :
    trame = select_trame(trames, numero)
    res = str( int(trame[46]+trame[47]+trame[48]+trame[49], 16) )
    return res

def getWindow() :
    trame = select_trame(trames, numero)
    res = str( int(trame[52]+trame[53], 16) )
    return res

def getType():
    trame = select_trame(trames, numero)
    if (trame[13]+trame[14] == "0800") :
        if ( trame[15][0] == "4" ) :
             res = "IPv4"
             return res
        if ( trame[15][0] == "6" ) :
             res = "IPv6"
             return res

def getHTTP():
    trame = select_trame(trames, numero)
    for i in range(0, len(trame)-3 ) :
        if (trame[i]+trame[i+1]+trame[i+2]+trame[i+3] == "0d0a0d0a") :
            #print(trame[i]+trame[i+1]+trame[i+2]+trame[i+3] )
            return "HTTP"

def getRequete():
    res = ""
    tO=tailleOpt()
    trame = select_trame(trames, numero)
    if (tO==0):
        for i in range(58, len(trame)-1 ) :
            if (trame[i]+trame[i+1] == "0d0a") :
                break
            elif (trame[i] == "0040" or trame[i] == "0050" or trame[i] == "0060" or trame[i] == "0070" or trame[i] == "0080") :
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
             print(res)

    byte_array = bytearray.fromhex(res)
    return byte_array.decode()
    #return res.decode("hex")

"""def thl_tcp():
    #Si thl>5, il y a des options
    trame = select_trame(trames, numero)
    res = (int(trame[49], 16))/10
    return res"""

def tailleOpt():
    trame = select_trame(trames, numero)
    thl = int(trame[49][0], 16)
    if (thl>5) :
        res = (thl*4)-20
        return res
    else:
        return 0

analyse_trame()
