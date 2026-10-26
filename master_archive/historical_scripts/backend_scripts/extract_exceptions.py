import io
import re

with io.open('compose_logs.txt', 'r', encoding='utf-8', errors='ignore') as f:
    text = f.read()

# Find all occurrences of HTTP 500 or Python Exceptions
print("--- 500 Errors ---")
for line in text.split('\n'):
    if '500 Internal Server Error' in line or ' 500 ' in line:
        print(line.strip())

print("\n--- Exception Traces ---")
matches = re.finditer(r'([a-zA-Z0-9_\.]+(Error|Exception)[^\n]*)', text)
unique_exceptions = set()
for m in matches:
    unique_exceptions.add(m.group(1).strip())

for e in unique_exceptions:
    print(e)
