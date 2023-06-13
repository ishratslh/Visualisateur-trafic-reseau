import pandas as pd
import numpy as np
import copiev as analyse
import pandas as pd
import numpy as np
import copiev as analyse
global count
information = ""
def create_dt(trames):
    df = pd.DataFrame(columns = ["Num", "Paquet", "Comments", "Protocol"])
    count = 0
    while (analyse.select_trame(trames, count)):
        analyse.analyse_trame(count, trames)
        if analyse.ty_pe != "IPv4":
            paquet = ""
            information = "Pas une trame Ethernet et/ou pas un protocol IPv4"
        
        elif analyse.protocol== "TCP" :
            information = analyse.protocol+ ": "+ analyse.portS + " -> " + analyse.portD +" "+  analyse.flags +" SeqNum : " +analyse.seq +"  AckNum : " + analyse.ack+" Win :"  + analyse.window
            paquet = "SOURCE Ip :" + analyse.ipSource +" Port : "+ analyse.portS +" --------" + analyse.flags + "-------> "+ "DESTINATION Ip :" + analyse.ipDest +" Port : " +analyse.portD
        elif analyse.protocol== "HTTP" :
            information = analyse.protocol+ ": " + analyse.requeteHTTP
            paquet = "SOURCE Ip :" + analyse.ipSource +" Port : "+ analyse.portS +" --------------------------> "+ "DESTINATION Ip :" + analyse.ipDest +" Port : " +analyse.portD
        else:
            if analyse.protocol== "ICMP":
                information = analyse.protocol+ "(+" + analyse.ty_pe +")"+ ": pas une trame de protocole TCP"
            if analyse.protocol== "UCP":
                information = analyse.protocol+ ": pas une trame de protocole TCP"
            if analyse.protocol== "ARP":
               information = analyse.protocol+ ": pas une trame de protocole TCP"
            else :
               information = "Pas une trame de protocole TCP"
            paquet = "SOURCE Ip :" + analyse.ipSource +" --------------------------------------> "+ "DESTINATION Ip :" + analyse.ipDest
        df.loc[count,["Num", "Paquet", "Comments", "Protocol"]] = [count,paquet, information, analyse.protocol]
        count+= 1
    #print(df)
    return df
