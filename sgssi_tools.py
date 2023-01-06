import sgssi_struct as ss
import os, datetime, hashlib

def install_package(module):

    t = ""
    s = "\'" + module + "\' module needs to be installed for this program to function. Do you want to install it? [Y/N]"
    while t != "Y" and t != "y" and t != "N" and t != "n":
        t = input(s)
    
    if t == "y" or t == "Y":
        os.system("pip install " + module)
    else:
        exit("Exiting program.")

try:
    from ripemd import ripemd160
except ModuleNotFoundError:
    install_package("ripemd-hash")
    from ripemd import ripemd160

try:
    import base58check
except ModuleNotFoundError:
    install_package("base58check")
    import base58check


def check_private_key():

    if ss.Direc.private != "":

        #Check if key exists
        if not os.path.isfile(ss.Direc.private):

            if ss.LOGS:
                print("Could not find introduced ECDSA private key.")
            get_private_key("")

    else: 
        
        while ss.Direc.name == "":
            ss.Direc.name = input("Introduce a name for the key pair ('_priv.pem/_pub.pem' will be added): ")
        if ss.LOGS:
            print("Generating private key with name: '" + ss.Direc.name + "' -> " + ss.Direc.name + "_priv.pem... ", end="")
        get_private_key(ss.Direc.name)
    
    ss.Direc.name, ss.Direc.path = get_name_from_private(ss.Direc.private)
    return ss.Direc.private


def check_public_key():

    if ss.Direc.public == "" or not os.path.isfile(ss.Direc.public):

        if ss.LOGS:
            print("Generating public key with name: '" + ss.Direc.name + "' -> " + ss.Direc.name + "_pub.pem... ", end="")
        get_public_key()

    return ss.Direc.public


def check_request():

    if (ss.Direc.certificate == "" and ss.Direc.request == "") or not os.path.isfile(ss.Direc.request):
        if ss.LOGS:
            print("Generating certificate request with name: '" + ss.Direc.name + "' -> " + ss.Direc.name + "_req.csr... ", end="")
        get_cert_request()
    

    return ss.Direc.request


def check_certificate():
    
    if ss.Direc.certificate == "" or not os.path.isfile(ss.Direc.certificate):

        if ss.Direc.request == "":
            ss.Direc.certificate = ""
            check_request()

        get_certificate()

def get_name_from_private(name):

    new_name = name.split("/")[-1]
    new_name = new_name.split(".pem")[0]

    if new_name.endswith("_priv"):

        new_name = new_name[:-5]

    path = "./" + "/".join(name.split("/")[:-1])

    return new_name, path

def create_dir_file():
    
    ss.Direc.file = ss.Direc.path + "/" + ss.Direc.name + "_dir.txt"
    with open(ss.Direc.file, "w") as f:
        f.write(ss.Direc.steps[10])

    return ss.Direc.file

def get_private_key(name):

    while name == "":
        name = input("Introduce a name for the key pair ('_priv.pem/_pub.pem' will be added): ")

    if not os.path.exists(name):
        os.makedirs(name)

    ss.Direc.private = name + "/" + name + "_priv.pem"
    os.system("openssl ecparam -name secp256k1 -genkey -noout -out " + str(ss.Direc.private))
    if ss.LOGS:
        print("Done.")


def get_public_key():

    ss.Direc.public = ss.Direc.path[2:] + "/" + ss.Direc.name + "_pub.pem"

    if os.path.exists(ss.Direc.public):
        os.remove(ss.Direc.public)

    os.system("openssl  ec -in " + ss.Direc.private + " -pubout > " + ss.Direc.public)
    if ss.LOGS:
        print("Done.")


def get_cert_request():

    ss.Direc.request = ss.Direc.path + "/" + ss.Direc.name + "_req.csr"

    if os.path.exists(ss.Direc.request):
        os.remove(ss.Direc.request)

    os.system("openssl req -new -keyform PEM -key " +  ss.Direc.private + " -out " + ss.Direc.request)
    if ss.LOGS:
        print("Done.")

def get_certificate():

    ss.Direc.certificate = ss.Direc.path + "/" + ss.Direc.name + "_cert.crt"

    if os.path.exists(ss.Direc.certificate):
        os.remove(ss.Direc.certificate)
    
    os.system("openssl x509 -req -days 365 -in " +  ss.Direc.request + " -signkey " + ss.Direc.private + " -out " + ss.Direc.certificate)
    if ss.LOGS:
        print("Done.")


def sign_file():

    if ss.LOGS:
        print("Signing file... ", end="")
    ss.Direc.signature = ss.Direc.path + "/" + ss.Direc.name + "_dir.sig"
    os.system("openssl dgst -c -sign " + ss.Direc.private + " -out " + ss.Direc.signature + " " + ss.Direc.file)
    if ss.LOGS:
        print("Done.")


def verify_sign():

    if ss.LOGS:
        print("Verifying file... ")
    os.system("openssl dgst -c -verify " + ss.Direc.public + " -signature " + ss.Direc.signature + " " + ss.Direc.file)

def sha256_on_file(file):
    
    sha256_hash = hashlib.sha256()

    try:
        with open(file, "rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except FileNotFoundError:
        print("File not found.")

def sha256_on_text(text):

    sha256_hash = hashlib.sha256()
    sha256_hash.update(text.encode('utf-8'))
    return sha256_hash.hexdigest()


def ripemd_on_text(text):

    ripemd = ripemd160.new()
    ripemd.update(bytes(text, 'UTF-8'))
    return ripemd.digest().hex()

def add_mark(text):

    return get_mark() + text

def get_mark():

    current_date = datetime.date.today()
    return str(current_date)[2:4]

def get_first_n_bytes(text, n):

    return bytes(text, 'utf-8')[:n].decode()

def get_base58(text):

    base58 = base58check.b58encode(str.encode(text))
    return base58.decode()