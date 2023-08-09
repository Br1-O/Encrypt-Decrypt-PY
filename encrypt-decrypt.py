import sqlite3
from cryptography.fernet import Fernet
import cryptography

from tkinter import *
from tkinter import messagebox as msgbox

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

###############################################################################################################################################
#Tkinter GUI :
###############################################################################################################################################

#Deficiones del Root:
root=Tk()
root.title("Programa para que Mati ya no te pregunte si sabes la nota v1.3")
root.geometry("800x500")
root.configure(background="#9090ff")

#Main Frame:
mainFrame = LabelFrame(root, text= """  Ingrese los datos del alumno que desea que Mati ya no le pregunte si sabe la nota:  """, fg="#3030ff", padx=5, pady=5, bg="#ffffff", borderwidth=5, bd=5, font=("", 13))
mainFrame.grid(row=1, column=0, pady=15, padx=(80,0))

#Results Frame:
secondFrame = LabelFrame(root, text= """  Los datos del alumno son:  """, fg="#3030ff", padx=5, pady=5, borderwidth=5, bg="#ffffff", bd=5, font=("", 13))
secondFrame.grid(row=4, column=0, pady=10, padx=(80,0))

#Labels:

name= Label(mainFrame, text="Nombre:", fg=("#3030ff"), bg=("#fff"), font=("", 11))
name.grid(row=0, column=0, pady=10)

dni= Label(mainFrame, text="DNI:", fg=("#3030ff"), bg=("#fff"), font=("", 11))
dni.grid(row=1, column=0, pady=(20,10))

# Form:

name= Entry(mainFrame, width=50, fg="#3030ff", borderwidth=2, font=("", 11))
name.grid(row=0, column=1, padx=20, pady= 10, ipadx=50)

dni= Entry(mainFrame, width=50, fg="#3030ff", borderwidth=2, font=("", 11))
dni.grid(row=1, column=1, padx=20, pady=(20, 10), ipadx=50)


#■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ FUNCTIONS ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■#

#■■■■■■■■■■■■ function to GENERATE KEY ■■■■■■■■■■■■■■#

def generateKey(seed):
    try:
        # Convertir la semilla en una clave segura
        seed_bytes=str(seed).encode()

        #Hashing of the string and getting the first 32 chars 
        kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                salt=b'',
                iterations=100000,
                length=32,
                backend=default_backend()
            )
        
        #Encode the seed as URL-safe after derive 
        key = base64.urlsafe_b64encode(kdf.derive(seed_bytes))
    except Exception as e:
        key=e
    return key

#■■■■■■■■■■■■ function to ENCODE MESSAGE ■■■■■■■■■■■■■■#

def encode(message, key):
    try:
        # Crea una instancia de Fernet con la clave
        f = Fernet(key)
        # Codifica el mensaje en bytes y luego cifra
        encrypted_message = f.encrypt(str(message).encode())
    except Exception as e:
        encrypted_message=e
    return encrypted_message

#■■■■■■■■■■■■ function to DECODE MESSAGE ■■■■■■■■■■■■■■#

def decode(encrypted_message, key):
    try:
        # Crea una instancia de Fernet con la clave
        f = Fernet(key)
        # Decifra el mensaje cifrado y luego lo decodifica a una cadena
        message = f.decrypt(encrypted_message).decode()
    except Exception as e:
        message=e
    return message

#■■■■■■■■■■■■ function to open encode/decode window ■■■■■■■■■■■■■■#

def openCodingWindow():
    #New window for encode/decode features:
    codingWindow=Tk()
    codingWindow.title("Encrypt-Decrypt v1.3")
    codingWindow.geometry("1550x820")
    codingWindow.configure(background="#9090ff")

    #■■■■■■■■■■■■ Encoding Frame ■■■■■■■■■■■■:
    encodingFrame = LabelFrame(codingWindow, text= """  Ingrese el mensaje a codificar:  """, fg="#3030ff", padx=5, pady=5, borderwidth=5, bg="#ffffff", bd=5, font=("", 13))
    encodingFrame.grid(row=0, column=0, pady=10, padx=(80,0))

    #content
    labelEncodeMsg= Label(encodingFrame, text="Mensaje:", fg=("#3030ff"), bg=("#fff"), font=("", 11))
    labelEncodeMsg.grid(row=0, column=0, pady=(20,10)) 

    message= Text(encodingFrame, width=50, fg="#3030ff", borderwidth=2, font=("", 11))
    message.grid(row=1, column=0, padx=20, pady= 10, ipadx=50)

    labelEncodeKey= Label(encodingFrame, text="Key (seed):", fg=("#3030ff"), bg=("#fff"), font=("", 11))
    labelEncodeKey.grid(row=2, column=0, pady=(20,10)) 

    key_encode= Entry(encodingFrame, width=50, fg="#3030ff", borderwidth=2, font=("", 11))
    key_encode.grid(row=3, column=0, padx=20, pady= 10, ipadx=50)

    key_encode=generateKey(key_encode.get())

    labelEncodeIterations= Label(encodingFrame, text="Numero de iteraciones:", fg=("#3030ff"), bg=("#fff"), font=("", 11))
    labelEncodeIterations.grid(row=4, column=0, pady=(20,10)) 

    key_iterations_encode= Entry(encodingFrame, width=50, fg="#3030ff", borderwidth=2, font=("", 11))
    key_iterations_encode.grid(row=5, column=0, padx=20, pady= 10, ipadx=50)

    #function to encode in window
    def encodeMessageInWindow():

        key_iterations_E=int(key_iterations_encode.get())

        encoded_message=encode(message.get("1.0", "end-1c"),key_encode)

        for i in range(1, key_iterations_E):
            encoded_message=encode(encoded_message,key_encode)

        labelEncodeMsg= Label(encodingFrame, text="Mensaje Encriptado:", fg=("#3030ff"), bg=("#fff"), font=("", 11))
        labelEncodeMsg.grid(row=0, column=0, pady=(20,10)) 

        message.delete("1.0", "end")

        message.insert("1.0", encoded_message)

    # Btn Encode:
    btnEncode= Button(encodingFrame, text="Codificar", width=50, bg="#8080ff", fg="#fff", borderwidth=2, font=("", 11), command=encodeMessageInWindow)
    btnEncode.grid(row=6, column=0, padx=10, pady=15, ipadx=40, columnspan=2)

    #■■■■■■■■■■■■ Decoding Frame ■■■■■■■■■■■■:
    decodingFrame = LabelFrame(codingWindow, text= """   Ingrese el mensaje a decodificar:  """, fg="#3030ff", padx=5, pady=5, borderwidth=5, bg="#ffffff", bd=5, font=("", 13))
    decodingFrame.grid(row=0, column=1, pady=10, padx=(80,0))

    #content
    labelDecode= Label(decodingFrame, text="Mensaje:", fg=("#3030ff"), bg=("#fff"), font=("", 11))
    labelDecode.grid(row=0, column=0, pady=(20,10)) 

    message_encrypted= Text(decodingFrame, width=50, fg="#3030ff", borderwidth=2, font=("", 11))
    message_encrypted.grid(row=1, column=0, padx=20, pady= 10, ipadx=50)

    labelDecodeKey= Label(decodingFrame, text="Key (seed):", fg=("#3030ff"), bg=("#fff"), font=("", 11))
    labelDecodeKey.grid(row=2, column=0, pady=(20,10)) 

    key_decode= Entry(decodingFrame, width=50, fg="#3030ff", borderwidth=2, font=("", 11))
    key_decode.grid(row=3, column=0, padx=20, pady= 10, ipadx=50)

    key_decode=generateKey(key_decode.get())

    labelDecodeIterations= Label(decodingFrame, text="Numero de iteraciones:", fg=("#3030ff"), bg=("#fff"), font=("", 11))
    labelDecodeIterations.grid(row=4, column=0, pady=(20,10)) 

    key_iterations_decode= Entry(decodingFrame, width=50, fg="#3030ff", borderwidth=2, font=("", 11))
    key_iterations_decode.grid(row=5, column=0, padx=20, pady= 10, ipadx=50)

    #function to encode in window
    def decodeMessageInWindow():

        key_iterations_D=(int(key_iterations_decode.get()))
        #loop to decode key_iterations_D times
        for i in range(1, key_iterations_D):
            decoded_message=decode(message_encrypted.get("1.0", "end-1c"),key_decode)
            decoded_message= decoded_message[2:-1]
            message_encrypted.delete("1.0", "end")
            message_encrypted.insert("1.0", decoded_message)

        #One last decode outside of the loop, so I avoid slicing the original decoded value
        decoded_message=decode(message_encrypted.get("1.0", "end-1c"),key_decode)
        message_encrypted.delete("1.0", "end")
        message_encrypted.insert("1.0", decoded_message)

        labelDecode= Label(decodingFrame, text="Mensaje Desencriptado:", fg=("#3030ff"), bg=("#fff"), font=("", 11))
        labelDecode.grid(row=0, column=0, pady=(20,10)) 

    # Btn Decode:
    btnDecode= Button(decodingFrame, text="Decodificar", width=50, bg="#8080ff", fg="#fff", borderwidth=2, font=("", 11), command=decodeMessageInWindow)
    btnDecode.grid(row=6, column=0, padx=10, pady=15, ipadx=40, columnspan=2)

#■■■■■■■■■■■■ Function to open pop-up message when closing window ■■■■■■■■■■■■:

def onClosing():
    if msgbox.askokcancel("¿Ya sabes tu nota?", "¡¿Estás seguro que sabes tu nota?! \n \n ¡No saber tu nota puede provocar que Mati te pregunte si ya viste tu nota!"):
        root.destroy()
root.protocol("WM_DELETE_WINDOW", onClosing)


#■■■■■■■■■■■■■■■■■■■■■■■■ function to actually do the thing, you know, the thing.. finding out our grades ■■■■■■■■■■■■■■■■■■■■■■■■■■#

def getGrade():
        
    try:
        #■■■■■■■■■■■■ db connection and fetch ■■■■■■■■■■■■■■#

            student=name.get()
            id=dni.get()

            conn= sqlite3.connect('db/notas.db')           
            c= conn.cursor()
            q='SELECT * FROM students WHERE name LIKE ?;'
            c.execute(q,('%'+student+'%',))
            row=c.fetchone()

            message=row[2]
        #■■■■■■■■■■■■ generating key via HMAC with our DNI as seed ■■■■■■■■■■■■■■#

            key = generateKey(id)

        #■■■■■■■■■■■■ decoding via Fernet object ■■■■■■■■■■■■■■#

            id_db=f'■ Id: {row[0]}'
            name_db=f'■ Nombre: {row[1]}'
            try:
                grade_decrypt=decode(message,key)
                grade=f'■ Nota: {grade_decrypt}'
            except cryptography.fernet.InvalidToken:
                grade='No se pudo obtener la nota por un error de desencriptación. (InvalidToken)'
            except Exception as e:
                grade=e

            for widget in secondFrame.winfo_children():
                widget.destroy()

            #Showing the results:
            id_print= Label(secondFrame, text=id_db, fg=("#3030ff"), bg=("#fff"), font=("", 11))
            id_print.grid(row=0, column=0, padx=20, pady= (20, 10), ipadx=30, columnspan=1)
            
            name_print= Label(secondFrame, text=name_db, fg=("#3030ff"), bg=("#fff"), font=("", 11))
            name_print.grid(row=1, column=0, padx=20, pady= (20, 10), ipadx=30, columnspan=1)
            
            grade_print= Label(secondFrame, text=grade, fg=("#3030ff"), bg=("#fff"), font=("", 11))
            grade_print.grid(row=2, column=0, padx=20, pady= (20, 10), ipadx=30, columnspan=1)


        #■■■ db connection and cursor closing ■■■#
            c.close()
            conn.close()

    except sqlite3.Error as error:
        error=f'Error: {error}'

        #Results:

        results= Label(secondFrame, text=error, width=50, fg="#3030ff", borderwidth=2, font=("", 11))
        results.grid(row=0, column=0, padx=20, pady=(20, 10), ipadx=50)

#■■■■■■■■■■■■■■■■■■■■■■■■ Btn submit and main loop of Tkinter GUI ■■■■■■■■■■■■■■■■■■■■■■■■■■#

# Btn Submit:
btnSubmit= Button(mainFrame, text="Saber nota", width=50, bg="#8080ff", fg="#fff", borderwidth=2, font=("", 11), command=getGrade)
btnSubmit.grid(row=7, column=0, padx=10, pady=15, ipadx=40, columnspan=2)

# Btn Submit:
btnSubmit= Button(mainFrame, text="Codificar - Decodificar mensaje", width=50, bg="#8080ff", fg="#fff", borderwidth=2, font=("", 11), command=openCodingWindow)
btnSubmit.grid(row=8, column=0, padx=10, pady=15, ipadx=40, columnspan=2)

#Ejecución de la Pantalla del Usuario:
root.mainloop()