import csv


def load_logs(path):
    with open(path, encoding="utf-8") as file:
        return list(csv.DictReader(file))
