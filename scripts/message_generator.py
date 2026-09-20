# message_generator.py
# Generates fake SWIFT message files on a timer, using field labels
# documented by BAE Systems (FIN 900 Confirmation of Debit, 20: Transaction,
# Sender :, 19A: Amount, etc.), mixed with other benign-looking message
# types so file content isn't 100% "malicious-looking" -- gives false
# positive testing something realistic to check against. Feeds Rule 5.

import random
import string
import time
import os
from datetime import datetime

OUTPUT_DIR = r"C:\Allians\mcm\in"
INTERVAL_SECONDS = 10

MESSAGE_TEMPLATES = [
    # The exact string the real malware searched for -- should be a
    # MINORITY of traffic, not the default.
    lambda umid, sender, trn, amount: f"""FIN 900 Confirmation of Debit
20: Transaction {trn}
Sender : {sender}
19A: Amount {amount}
62F: {amount}
""",
    lambda umid, sender, trn, amount: f"""FIN 900 Confirmation of Credit
20: Transaction {trn}
Sender : {sender}
19A: Amount {amount}
60F: {amount}
""",
    lambda umid, sender, trn, amount: f"""MT950 Statement
20: Transaction {trn}
Sender : {sender}
62M: {amount}
60M: {amount}
""",
    lambda umid, sender, trn, amount: f"""20: Transaction {trn}
Sender : {sender}
Debit/Credit : D
90B: Price {amount}
""",
]

def random_bic():
    return ''.join(random.choices(string.ascii_uppercase, k=4)) + "XXX"

def random_trn():
    return f"TRN{datetime.now().strftime('%Y%m%d')}{random.randint(1000,9999)}"

def random_umid():
    return f"UMID{random.randint(10000,99999)}"

def generate_message():
    umid = random_umid()
    sender = random_bic()
    trn = random_trn()
    amount = round(random.uniform(500, 200000), 2)

    template = random.choice(MESSAGE_TEMPLATES)
    content = template(umid, sender, trn, amount)

    filename = f"{umid}.prc"
    filepath = os.path.join(OUTPUT_DIR, filename)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(filepath, "w") as f:
        f.write(content)

    print(f"[{datetime.now()}] Generated {filename} -- {sender}, {trn}, {amount}")

if __name__ == "__main__":
    print(f"Starting dummy SWIFT message generator, writing to {OUTPUT_DIR}")
    while True:
        generate_message()
        time.sleep(INTERVAL_SECONDS)
