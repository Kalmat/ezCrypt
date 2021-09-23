arguments = {
    "Usage": "python3 crypto.py ARGUMENT [OPTIONS]",
    "Values": {
        "-e": {"Name": "encrypt", "Help": "Encrypt data"},
        "-d": {"Name": "decrypt", "Help": "Decrypt data"},
        "-g": {"Name": "generate key", "Help": "Generate key"},
    },
    "MinArg": 1,
    "MaxArg": 1,
    "MutExc": [("-e", "-d", "-g")],
    "FreeArgs": False,
    "FreeArgsDesc": "",
    "MinFreeArgs": 0,
    "MaxFreeArgs": 0
}

options = {
    "Values": {
        "-i": {"Name": "input file", "isFlag": False, "FreeValues": False, "NoContent": "Ignore", "Help": "Input file to Encrypt/Decrypt"},
        "-iq": {"Name": "QR input file", "isFlag": False, "FreeValues": False, "NoContent": "Ignore", "Help": "Input file in QR format (.png only)"},
        "-m": {"Name": "message", "isFlag": False, "FreeValues": True, "NoContent": "Ignore", "Help": "Message to Encrypt/Decrypt"},
        "-o": {"Name": "output file", "isFlag": False, "FreeValues": False, "NoContent": "Ignore", "Help": "Output file to write encrypted/decrypted data or key"},
        "-oq": {"Name": "QR output file", "isFlag": False, "FreeValues": False, "NoContent": "Ignore", "Help": "Output file in QR format (.png)"},
        "-p": {"Name": "password", "isFlag": False, "FreeValues": True, "NoContent": "Ignore", "Help": "Password to Encrypt/Decrypt data (use quotation marks if required)"},
        "-k": {"Name": "key", "isFlag": False, "FreeValues": False, "NoContent": "Ignore", "Help": "Key to Encrypt/Decrypt data"}
    },
    "MutExc": [("-i", "-iq", "-m"), ("-o", "-oq"), ("-k", "-p")],
    "RequiredIf": []
}

arg_opt = {
    "-g": {"Required": [], "RequiredIf": [], "MutExc": [], "Ignored": ["-i", "-iq", "-m", "-k"]}
}
