import csv


def filter_csv_by_country(country_code, filename='ip2location.CSV'):
    filtered_rows = []

    with open(filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row[2] == country_code:
                filtered_rows.append(row)

    return filtered_rows
