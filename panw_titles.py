import re
from bs4 import BeautifulSoup
import requests
import argparse

def normalize_wrapped_text(text):
    """
    Normalize wrapped text by:
    - Collapsing all whitespace into single spaces.
    - Adding spaces between words that may have been joined during extraction.
    """
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'([a-z])([A-Z])', r'\1 \2', text)
    return text

def find_similar_elements(url, example_text, user_agent=None):
    """Find and extract text from elements similar to the example on a webpage."""
    # Default user-agent string (if not provided)
    if user_agent is None:
        user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/112.0.0.0 Safari/537.36"
        )
    
    headers = {"User-Agent": user_agent}

    # Fetch the HTML content from the URL with custom headers
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}")
        return
    
    soup = BeautifulSoup(response.text, "html.parser")
    
    # Locate the tag containing the example text
    element = soup.find(string=lambda text: text and example_text in text)
    
    if not element:
        print(f"Could not find the example text: {example_text}")
        return
    
    # Get the parent tag of the example text
    parent_tag = element.parent
    print(f"Found example text in tag: <{parent_tag.name} class='{parent_tag.get('class')}'>\n")

    # Find all elements with the same tag and class
    similar_elements = soup.find_all(parent_tag.name, class_=parent_tag.get("class"))
    
    for similar in similar_elements:
        cleaned_text = normalize_wrapped_text(similar.get_text())
        print(cleaned_text)


def fetch_html_from_url(url):
    """Fetch the HTML content from the given URL."""
    response = requests.get(url)
    response.raise_for_status()
    return response.text



def main():
    # Set up argparse
    parser = argparse.ArgumentParser(description="Extract text from similar HTML elements on a webpage.")
    parser.add_argument("-u", "--url", help="The URL of the webpage to scrape.")
    parser.add_argument("-t", "--text", help="Example text to find similar elements.")
    args = parser.parse_args()

    # Check if URL and text are provided, otherwise prompt interactively
    if args.url and args.text:
        find_similar_elements(args.url, args.text)
    else:
        url = input("Enter the URL of the webpage: ").strip()
        example_text = input("Enter the example text to search for: ").strip()
        find_similar_elements(url, example_text)

if __name__ == "__main__":
    main()
