import csv
def load_payloads_from_csv(path="payloads.csv"):
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return [row['payload'] for row in reader]

self.payloads = load_payloads_from_csv("payloads.csv")
