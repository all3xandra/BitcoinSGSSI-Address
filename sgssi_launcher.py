import argparse
import sgssi_dirs as sd

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='Bitcoin-like direction generator for SGSSI subject in UPV/EHU. For further information, review the documentation.')
    
    dirsopt = parser.add_mutually_exclusive_group()

    parser.add_argument('--mode', help='Direction, key and hash generator options are mutually exclusive.', choices=('gendir', 'genecdsa', 'gencert', 'hash'), required=True)

    dirsopt.add_argument('-priv', '--PRIVATE-KEY', default="",
                        type=str, help='Path to the ECDSA private key from actual path. Empty to create private and public pair of keys.')
    parser.add_argument('-pub', '--PUBLIC-KEY', default="",
                        type=str, help='Path to the ECDSA public key from actual path. Empty to create public key.')
    dirsopt.add_argument('-n', '--NAME', default="",
                        type=str, help='Name to be used in the creation of both private and public key if neccesary.')
    parser.add_argument('-s', '--SIGN', action=argparse.BooleanOptionalAction,
                        default=False, type=bool, help='Sign final direction with private key.')
    
    parser.add_argument('-req', '--CERTREQ', default="",
                        type=str, help='Certificate request file to get the certificate. New one will be created if private key is not provided and it has different path.')
    dirsopt.add_argument('-f', '--FILE', default="",
                        type=str, help='File to be signed.')
    parser.add_argument('-v', '--VERIFY', action=argparse.BooleanOptionalAction,
                        default=False, type=bool, help='Check if signing was done correctly, meaning the public key is correctly associated to the certificate used.')

    hashes = parser.add_mutually_exclusive_group()
    hashes.add_argument('-sha256f', '--SHA256FILE', default="",
                        type=str, help='Path to the file of which it will print the sha-256 hash on console.')
    hashes.add_argument('-sha256t', '--SHA256TEXT', default="",
                        type=str, help='Text of which it will print the sha-256 hash on console.')
    hashes.add_argument('-r160t', '--RIPEMD160TEXT', default="",
                        type=str, help='Text of which it will print the ripemd-160 hash on console.')
    hashes.add_argument('-b58', '--BASE58', default="",
                        type=str, help='Text of which base 58 will be printed on console.')

    parser.add_argument('-l', '--LOGS', action=argparse.BooleanOptionalAction,
                        default=False, type=bool, help='Enables logs on console.')

    args = parser.parse_args()
    sd.dirs_init(args)







