from tkinter import *
import pandas as pd
from tkinter import ttk
from tkinter.filedialog import *
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from functools import partial
import dataframe2 as dataframe2
import copiev as analyse

df = pd.DataFrame()
#Les colonnes sont ["Num", "Paquet", "Comments", "Protocol"]
filter_column="Protocol"


def read_file():
        global df
        global filename
        filename = askopenfilename(title="Ouvrir le fichier")

        if filename:
            try:
                filename = r"{}".format(filename)
                label1.delete(0, END)
                label1.insert(0, filename)
                #Lancer le traitement du fichier trace et retourner le df finale
                analyse.trames = filename
                df = dataframe2.create_dt(analyse.trames)
                #print(df)
            except ValueError:
                label1.config(text="File could not be opened")
            except FileNotFoundError:
                label1.config(text="File Not Found")
        def save_df_as_pdf():
         #dataframe en pdf
            fig, ax =plt.subplots(figsize=(12,4))
            ax.axis('tight')
            ax.axis('off')
            the_table = ax.table(cellText=df.values,colLabels=df.columns,loc='center')
            pp = PdfPages("FlowGraph.pdf")
            pp.savefig(fig, bbox_inches='tight')
            pp.close()
                
        #set_treeview()
        def set_treeview(): #Remplir le Treeview par les données dans le dataframe
                def select_value(e=None):  # cleaning tree and populating with df values
                    #print('hikhlvipvvvvvvvvvvpifhdfsi')
                    #print(df)
                    tree.delete(*tree.get_children())
                    if Combo.get() == "All flows":  # if All selected as column or value
                        [tree.insert("", "end", text=index, values=list(row)) for index, row in df.iterrows()]
                    else:
                        for index, row in df.loc[df[filter_column].eq(Combo.get())].iterrows():
                            tree.insert("", "end", text=index, values=list(row))
                            
                #Paramétrage:
                #liste_p=['All'] + list(df[filter_column].unique()) # Ajouter l'option All à la liste des protocoles
                #Remplir le treeview
                #print('hi')
                #print(df.columns)
                #print(df)
                tree["column"] = list(df.columns)
                tree["show"] = "headings"
                scrollbar.pack(side="right", fill="y")
                
                for col in tree["column"]:
                    tree.heading(col, text=col)
                tree.column('Num', minwidth = 30, width = 40, stretch = False)
                tree.column('Paquet', minwidth = 100, width = 800, stretch = False)
                tree.column('Comments', minwidth = 100, width = 700, stretch = False)
                tree["displaycolumns"]=('Num', 'Paquet', 'Comments')    
                df_rows = df.to_numpy().tolist()
                #print(df_rows)
                for row in df_rows:
                    tree.insert("", "end", values=row)
                #Texte
                #label = Label(root, text="Graphique de flux\n\n")
                #Le choix du protocole 
                labelTop = Label(root,text = "Type de flux")
                values=["All flows","TCP", "HTTP"]
                Combo = ttk.Combobox(root,values=["All flows","TCP", "HTTP"],state="readonly")
                Combo.bind("<<ComboboxSelected>>",select_value )
                
                
                #Configurer l'emplacement des briques
                #label.pack()
                tree.pack(expand=TRUE, fill=BOTH)
                labelTop.pack()
                Combo.pack()
                
        

        clear_treeview()
        set_treeview()
        save_df_as_pdf()


def clear_treeview():
    tree.delete(*tree.get_children())



        


################################################################################################
##Code de l'outil visualisateur affichant les données du réseau  (les résultats du traitement)##
################################################################################################


root = Tk()
root.title("Visualisateur Reseaux")
label1 = ttk.Entry(root, width=100)
label2 = Label(root) #Espace Vide ! pour séparer le label du treeview
button = ttk.Button(root, text="Ouvrir le fichier source", command=read_file)
#Texte
label = Label(root, text="Graphique de flux\n\n")
label.pack()
#Initialiser le treeview dans lequel on va afficher les résulats finales
tree = ttk.Treeview(root, columns=('time_seq', 'Packet', 'Comments'))
scrollbar = Scrollbar(root, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y")

#tree.configure(scrollregion =scrollbar.bbox("all"))
Combo = ttk.Combobox(root,state="readonly")

#""""""""""""""""""" Configurer l'affichage principal """"""""""""""""""""""""#
button.pack()
label1.pack()
label2.pack()


mainloop()
