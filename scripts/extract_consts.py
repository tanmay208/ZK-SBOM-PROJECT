import re

def parse_nested_brackets(text, start_idx):
    depth = 0
    in_bracket = False
    for i in range(start_idx, len(text)):
        if text[i] == '[':
            depth += 1
            in_bracket = True
        elif text[i] == ']':
            depth -= 1
            if depth == 0 and in_bracket:
                return text[start_idx:i+1], i+1
    return "", -1

def extract():
    with open("scripts/consts.nr", "r") as f:
        content = f.read()
    
    out = "POSEIDON_CONSTANTS = {\n"
    
    configs = [2, 3, 4, 5, 9]
    for t in configs:
        marker = f"x5_{t}_config() -> PoseidonConfig<{t},"
        idx = content.find(marker)
        if idx == -1:
            print(f"Could not find marker for t={t}")
            continue
            
        config_idx = content.find("config(", idx)
        
        # Now find the 4 main arrays: rc, mds, presparse, sparse
        # We look for '[' after config_idx
        idx1 = content.find('[', config_idx)
        rc_str, next_idx = parse_nested_brackets(content, idx1)
        
        idx2 = content.find('[', next_idx)
        mds_str, next_idx = parse_nested_brackets(content, idx2)
        
        idx3 = content.find('[', next_idx)
        presparse_str, next_idx = parse_nested_brackets(content, idx3)
        
        idx4 = content.find('[', next_idx)
        sparse_str, next_idx = parse_nested_brackets(content, idx4)
        
        # Now we parse the numbers out of these strings
        rc_flat = [int(x.strip(), 16) for x in rc_str.replace('\n', '').replace('[', '').replace(']', '').split(',') if x.strip()]
        
        mds_flat = [int(x.strip(), 16) for x in mds_str.replace('\n', '').replace('[', '').replace(']', '').split(',') if x.strip()]
        mds = [mds_flat[i*t:(i+1)*t] for i in range(t)]
        
        presparse_flat = [int(x.strip(), 16) for x in presparse_str.replace('\n', '').replace('[', '').replace(']', '').split(',') if x.strip()]
        presparse = [presparse_flat[i*t:(i+1)*t] for i in range(t)]
        
        sparse_flat = [int(x.strip(), 16) for x in sparse_str.replace('\n', '').replace('[', '').replace(']', '').split(',') if x.strip()]
        
        # we need to get rp. it's the 3rd argument to config()
        rp_arr = [0, 0, 56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]
        rp = rp_arr[t]
        
        out += f"    {t}: {{\n"
        out += f"        'rp': {rp},\n"
        out += f"        'rc': {rc_flat},\n"
        out += f"        'mds': {mds},\n"
        out += f"        'presparse_mds': {presparse},\n"
        out += f"        'sparse_mds': {sparse_flat}\n"
        out += "    },\n"
        
    out += "}\n"
    
    with open("backend/shared/crypto/poseidon_constants.py", "w") as f:
        f.write(out)

if __name__ == "__main__":
    extract()
