import sys
import lief

# Function to check if the file is a Mach-O file
def is_macho(file_path):
    return lief.is_macho(file_path)

# Function to check for NX flag
def has_nx(macho):
    return macho.has_nx

def has_pie(macho):
    return macho.is_pie

def has_canary(macho):
    stk_check = '___stack_chk_fail'
    stk_guard = '___stack_chk_guard'

    has_stk_check = any(str(func).strip() == stk_check for func in macho.imported_functions)
    has_stk_guard = any(str(func).strip() == stk_guard for func in macho.imported_functions)
    
    return has_stk_check and has_stk_guard


def has_arc(macho):
    for func in macho.imported_functions:
        if str(func).strip() in ('_objc_release', '_swift_release'):
            return True
    return False

def has_rpath(macho):
    return macho.has_rpath

def has_code_signature(macho):
    try:
        return macho.code_signature.data_size > 0
    except Exception:
        return False
    
def is_encrypted(macho):
    try:
        return bool(macho.encryption_info.crypt_id)
    except Exception:
        return False

# ... define other check functions similarly ...

# Function to perform all checks and return a report
def checksec(file_path):
    if not is_macho(file_path):
        return {"error": "File is not a Mach-O binary."}

    macho = lief.parse(file_path)
    return {
        "ARC": has_arc(macho),
        "Canary": has_canary(macho),
        #"Code Signature": has_code_signature(macho),
        #"Encrypted": is_encrypted(macho),
        #"NX": has_nx(macho),
        #"PIE": has_pie(macho),
        #"RPATH": has_rpath(macho),
        
        # ... call other check functions and add their results here ...
    }




# Function to print the results in a formatted way
def print_results(results):
    for key, value in results.items():
        print(f"{key}: {value}")

# Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <filename>")
        return

    filename = sys.argv[1]
    results = checksec(filename)
    print_results(results)

# This ensures that main() is only called when the script is run directly
if __name__ == "__main__":
    main()
