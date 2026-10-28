import os

EXCLUDE_DIRS = {'.git', '.venv', '.pytest_cache', '__pycache__', 'node_modules', '.next', 'target', '.bin', 'alembic'}
EXCLUDE_EXTS = {'.pyc', '.pyd', '.pyi', '.exe', '.dll', '.tar.gz', '.jsonl', '.proof', '.mutated', '.mutated2'}

def scan_dir(root_dir):
    inventory = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for f in filenames:
            ext = os.path.splitext(f)[1]
            if ext in EXCLUDE_EXTS: continue
            
            full_path = os.path.join(dirpath, f)
            rel_path = os.path.relpath(full_path, root_dir)
            inventory.append(rel_path.replace('\\\\', '/'))
    return sorted(inventory)

files = scan_dir('.')
with open('docs/security/audit/53_FILE_LEVEL_INVENTORY.md', 'w', encoding='utf-8') as out:
    out.write('# Phase 1: Complete Repository Inventory\n\n')
    out.write('## File-to-Purpose Inventory\n\n')
    
    dirs = {}
    for f in files:
        dirname = os.path.dirname(f)
        if dirname not in dirs: dirs[dirname] = []
        dirs[dirname].append(os.path.basename(f))
        
    for d, flist in dirs.items():
        dir_name = d if d else "Root"
        out.write(f'### `{dir_name}`\n')
        for f in flist:
            out.write(f'- `{f}`: \n')
        out.write('\n')
        
print('Done!')
