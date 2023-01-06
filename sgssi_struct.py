class Direction:
    def __init__(self, private, public, request, file, name, sign, verify):
        self.private = private
        self.public = public
        self.request = request
        self.certificate = ""
        self.file = file
        self.signature = ""
        self.name = name
        self.path = ""
        self.sign = sign
        self.verify = verify
        self.steps = ["" for i in range(11)]

    def __str__(self):
        return f"    PRIVATE KEY: {self.private}\n    PUBLIC KEY: {self.public}\n    REQUEST: {self.request}\n    CERTIFICATE: {self.certificate}\n    FILE: {self.file}\n    SIGNATURE: {self.signature}\n    PATH: {self.path}\n    NAME: {self.name}\n    SIGN: {self.sign}\n    STEPS: {[s for s in self.steps]}\n"

Direc = None
LOGS = False