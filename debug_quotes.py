
with open("main.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

total_occurrences = 0
for i, line in enumerate(lines):
    occurrences = line.count('"""')
    if occurrences > 0:
        total_occurrences += occurrences
        print(f"Line {i+1} has {occurrences} quotes: {line.strip()[:60]}...")

print(f"Total triple quotes: {total_occurrences}")
if total_occurrences % 2 != 0:
    print("ODD NUMBER OF TRIPLE QUOTES DETECTED! SYNTAX ERROR LIKELY.")
else:
    print("Even number of triple quotes.")
