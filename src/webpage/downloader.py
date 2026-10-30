import requests

def download_page(url):
    """
    Download the HTML content of a webpage.
    """

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0 Safari/537.36"
        )
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        response.raise_for_status()

        return response.text

    except Exception as e:
        print("Download Error:", e)
        return None


if __name__ == "__main__":

    url = input("Enter URL: ")

    html = download_page(url)

    if html:
        print("\nDownloaded Successfully!\n")
        print(html[:500])