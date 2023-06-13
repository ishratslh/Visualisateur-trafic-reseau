# Visualisateur trafic réseau

![alt text](https://pandorafms.com/blog/wp-content/uploads/2020/10/analisis-de-trafico-de-red-featured.jpg)

## Présentation

L'objectif de ce projet est de programmer un visualisateur des flux de trafic réseau.
Le flux de trafic correspond aux trames échangées dans le cadre d’un protocole
exécuté par deux machines.

Le visualisateur prendra en entrée un fichier trace au format texte contenant les
octets capturés préalablement sur un réseau Ethernet.


## Description du projet

Notre choix a été de coder en python, et notre projet se compose de plusieurs fichiers:
- copiev.py :
Ce fichier contient le code source qui permet d'analyser les trames de chacune de nos fichiers trace.txt, afin d'en isoler les informations pertinentes.

- dataframe2.py : Ce fichier permet de faire la selection de nos informations à l'aide de copiev.py afin de les stocker pour ensuite les afficher sur l'interface graphique.

- graph2.py : Ce fichier permet de mettre en place notre interface graphique à partir de la dataframe, tout en génerant le fichier pdf.

- trace.txt (ou n'importe quel autre fichier.txt): Le fichier trace au format texte contenant les octets capturés préalablement sur un réseau Ethernet.

- le Makefile, le howto & le README

## Description du code source

Notre code source contient plusieurs fonctions :
- analyse_trame() : fonction principale qui va faire tourner toutes les fonctions ci-dessous.

- list_trame() : convertit le fichier texte en liste de trames.

- select_trame() : retourne une trame en particulier à analyser.

- addIPSource(), addIPDest() : retournent les adresses IP des deux machines executant le protocole.

- getProtocol() : retourne le protocole.

- getHTTP() : analyse si le protocole est HTTP ou non.

- tcp_portS(), tcp_portD() : retournent les ports des machines dans le cas d'un protocole TCP

- getSEQ(), getACK(), getWindow() : retournent le n° de séquence, d'acquittement et la fenêtre.

- getType() : retourne "IPv4" ou "IPv6" en fonction de la trame.

- tcp_flags() : retourne les drapeaux TCP.

- thl_tcp() : retourne la valeur du champ THL, qui va indiquer si on a une taille d'entete avec ou sans options.

- getRequete() : retourne la requête HTTP

- tailleOpt() : retourne la taille des options

## A propos de la vidéo

Nous avons effectué quelques modifications sur le code du projet après la publication de la vidéo :

- On a rajouté la fonctionnalité de filtrage selon le protocole.

- On peut choisir le fichier depuis l'interface.

## Informations complémentaires sur nos fichiers trace

- tracehttp.txt : permet de tester des trames HTTP

- traceT.txt : un des fichiers de la vidéo

- trace.txt : un des fichiers de la vidéo
