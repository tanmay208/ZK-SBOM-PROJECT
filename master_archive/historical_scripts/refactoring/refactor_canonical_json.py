import glob
import re

files = glob.glob("e:/Main Project/backend/shared/tests/*.py")

for file in files:
    with open(file, "r", encoding="utf-8") as f:
        content = f.read()
    
    # We want to replace canonicalizer._canonical_json(comp, purl)
    # with canonicalizer._canonical_json(comp.name, purl, comp.version)
    # The variable for comp might be `comp` or `c` etc, but it's always `comp` in our grep results.
    new_content = re.sub(
        r'_canonical_json\((comp)(?:\.parsed)?,\s*([^)]+)\)',
        r'_canonical_json(\1.name, \2, \1.version)',
        content
    )
    
    if new_content != content:
        with open(file, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"Updated {file}")
