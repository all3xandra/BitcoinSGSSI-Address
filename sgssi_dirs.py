import sgssi_tools as st
import sgssi_struct as ss

def dirs_init(params):

    ss.LOGS = params.LOGS
    ss.Direc = ss.Direction(params.PRIVATE_KEY, params.PUBLIC_KEY, params.CERTREQ, params.FILE, params.NAME, params.SIGN, params.VERIFY)

    if params.mode == "gendir":

        print("Generating bitcoin-like direction for SGSSI...")
        print("Generated SGSSI direction: " + direction_generator())
        
        if ss.Direc.sign:

            st.create_dir_file()
            st.sign_file()

            if ss.Direc.verify:
                st.verify_sign()

    elif params.mode == "genecdsa":

        print("Generating ECDSA key pair...")
        ss.Direc.private = st.check_private_key()
        ss.Direc.public = st.check_public_key()
        print("\nKeys generated.")

    elif params.mode == "gencert":

        print("Generating certificate...")
        ss.Direc.private = st.check_private_key()
        ss.Direc.request = st.check_request()
        ss.Direc.certificate = st.check_certificate()

        print("Certificate process finished.")

    else:

        if params.SHA256FILE != "":
            print("Generating sha-256 hash on " + params.SHA256FILE + " file:")
            print(st.sha256_on_file(params.SHA256FILE))

        elif params.SHA256TEXT != "":
            print("Generating sha-256 hash on text: " + params.SHA256TEXT)
            print(st.sha256_on_text(params.SHA256TEXT))
    
        elif params.RIPEMD160TEXT != "":
            print("Generating ripemd-160 on text: " + params.RIPEMD160TEXT)
            print(st.ripemd_on_text(params.RIPEMD160TEXT))

        elif params.BASE58 != "":
            print("Generating base 58 on text: " + params.BASE58)
            print(st.get_base58(params.BASE58))
        
        else:
            print("An algorithm needs to be chosen alongside its parameter.")


def direction_generator():

    ss.Direc.steps[0] = st.check_private_key()
    if ss.LOGS:
        print("Step 0: Using ECDSA private key -> " + ss.Direc.steps[0])

    ss.Direc.steps[1] = st.check_public_key()
    if ss.LOGS:
        print("Step 1: Using ECDSA public key -> " + ss.Direc.steps[1])

    ss.Direc.steps[2] = st.sha256_on_file(ss.Direc.public)
    if ss.LOGS:
        print("Step 2: Applying SHA-256 algorithm on '" + ss.Direc.steps[1] + "' ECDSA public key ->\n        " + ss.Direc.steps[2])

    ss.Direc.steps[3] = st.ripemd_on_text(ss.Direc.steps[2])
    if ss.LOGS:
        print("Step 3: Applying RIPEMD-160 algorithm on 'Step 2' -> " + ss.Direc.steps[3])

    ss.Direc.steps[4] = st.add_mark(ss.Direc.steps[3])
    if ss.LOGS:
        print("Step 4: Adding SGSSI version mark '" + st.get_mark() + "' on 'Step 3' -> " + ss.Direc.steps[4])

    ss.Direc.steps[5] = st.sha256_on_text(ss.Direc.steps[4])
    if ss.LOGS:
        print("Step 5: Applying SHA-256 algorithm on 'Step 4' -> " + ss.Direc.steps[5])

    ss.Direc.steps[6] = st.sha256_on_text(ss.Direc.steps[5])
    if ss.LOGS:
        print("Step 6: Applying SHA-256 algorithm on 'Step 5' -> " + ss.Direc.steps[6])

    ss.Direc.steps[7] = st.get_first_n_bytes(ss.Direc.steps[6], 4)
    if ss.LOGS:
        print("Step 7: Get first 4 bytes from 'Step 6' -> " + ss.Direc.steps[7])

    ss.Direc.steps[8] = ss.Direc.steps[4] + ss.Direc.steps[7]
    if ss.LOGS:
        print("Step 8: Add 'Step 7' to 'Step 4' -> " + ss.Direc.steps[8])

    ss.Direc.steps[9] = st.get_base58(ss.Direc.steps[8])
    if ss.LOGS:
        print("Step 9: Convert 'Step 8' to base 58 codification -> " + ss.Direc.steps[9])

    ss.Direc.steps[10] = ss.Direc.steps[9][:8]
    if ss.LOGS:
        print("Step 10: Get first 8 characters of the generated direction -> " + ss.Direc.steps[10])

    return ss.Direc.steps[10]