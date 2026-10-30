from downloader import download_page
from parser import parse_html

url = input("Enter URL: ")

html = download_page(url)

if html:

    features = parse_html(html)

    print("\nExtracted Features\n")

    for key, value in features.items():
        print(f"{key}: {value}")