import requests
from bs4 import BeautifulSoup
import sys

def search(query):
    search_url = f"https://duckduckgo.com/html/?q={query} asn ip"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    try:
        response = requests.get(search_url, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        h2_tags = soup.find_all('h2')

        return h2_tags

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

def extract_asn_number(tag):
    asn_number = tag.find_next('a').text
    return asn_number

def extract_as_numbers(h2_tags):
    as_numbers = [extract_asn_number(tag) for tag in h2_tags]
    return as_numbers

def main(domain):
    query = domain
    h2_tags = search(query)

    if h2_tags:
        as_numbers = extract_as_numbers(h2_tags)

        if as_numbers:
            print("Extracted AS Numbers:")
            for index, asn_number in enumerate(as_numbers, 1):
                print(f"AS Number {index}: {asn_number}")
        else:
            print("No AS Numbers found in the search results.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <domain>")
        sys.exit(1)

    domain_argument = sys.argv[1]
    main(domain_argument)
    
