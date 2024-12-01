import requests
import json
import time
import re
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

class IdentityService:
    
    def __init__(self, api_key, user_agent='IX-Python/0.6'):
        self.API_KEY = api_key
        self.USER_AGENT = user_agent
        self.API_ROOT = 'https://3.intelx.io'
        self.HEADERS = {'X-Key': self.API_KEY, 'User-Agent': self.USER_AGENT}
        self.PAUSE_BETWEEN_REQUESTS = 1
        self.session = requests.Session()  # Use session to reuse connections

        # CourtListener API token and base URL
        self.COURTLISTENER_API_TOKEN = "e4eb8d9835f17311a52ff962981a1202d1765d39"
        self.COURTLISTENER_BASE_URL = "https://www.courtlistener.com/api/rest/v4/search/"

    def get_search_results(self, search_id, format=1, maxresults=100):
        params = {'id': search_id, 'format': format, 'limit': maxresults}
        try:
            r = self.session.get(f'{self.API_ROOT}/live/search/result', params=params, headers=self.HEADERS)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching search results: {e}")
            return None

    def idsearch(self, term, maxresults=100, buckets="", timeout=5, datefrom="", dateto="", terminate=[], analyze=False, skip_invalid=False):
        p = {
            "selector": term,
            "bucket": buckets,
            "skipinvalid": skip_invalid,
            "limit": maxresults,
            "analyze": analyze,
            "datefrom": datefrom,
            "dateto": dateto,
            "terminate": terminate,
        }
        
        try:
            print(f"Starting search for: {term}")
            r = self.session.get(f'{self.API_ROOT}/live/search/internal', headers=self.HEADERS, params=p)
            r.raise_for_status()
            search_data = r.json()
            search_id = search_data.get('id')
            
            if not search_id:
                print(f"Search failed. Response: {search_data}")
                return None
            
            print(f"Search ID: {search_id}")
        except requests.exceptions.RequestException as e:
            print(f"Error initiating search: {e}")
            return None

        done = False
        results = []
        while not done:
            time.sleep(self.PAUSE_BETWEEN_REQUESTS)
            result = self.get_search_results(search_id, maxresults=maxresults)
            
            if result is None:
                print(f"No results received for search ID: {search_id}")
                break
            
            if result["status"] == 0 and result["records"]:
                results.extend(result['records'])
                maxresults -= len(result['records'])
            elif result['status'] == 2 or maxresults <= 0:
                done = True
            elif result['status'] == 3:
                self.terminate_search(search_id)
                done = True
        
        return results

    def terminate_search(self, search_id):
        try:
            r = self.session.get(f'{self.API_ROOT}/live/search/internal', headers=self.HEADERS, params={"id": search_id})
            r.raise_for_status()
            print("Search terminated successfully.")
            return r.json()
        except requests.exceptions.RequestException as e:
            print(f"Error terminating search: {e}")
            return None

    def search_courtlistener(self, query, search_type="o", highlight=False, page=1, per_page=100):
        headers = {
            'Authorization': f'Token {self.COURTLISTENER_API_TOKEN}'
        }
        params = {
            'q': query,
            'type': search_type,
            'highlight': 'on' if highlight else 'off',
            'page': page,
            'per_page': per_page
        }

        try:
            response = requests.get(self.COURTLISTENER_BASE_URL, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error with CourtListener search: {e}")
            return None

    def display_courtlistener_results(self, results):
        if not results or 'results' not in results:
            return {"error": "No results found."}

        formatted_results = {
            "count": results.get("count", 0),
            "results": []
        }

        for result in results['results']:
            case_data = {
                "case_name": result.get('caseNameFull', 'No Case Name'),
                "date_filed": result.get('dateFiled', 'N/A'),
                "citation": ", ".join(result.get('citation', [])),
                "court": result.get('court', 'N/A'),
                "judge": result.get('judge', 'N/A'),
                "docket_number": result.get('docketNumber', 'N/A'),
                "case_url": result.get('url', 'No URL'),
                "case_id": result.get('id', 'N/A'),
                "snippet": result.get('opinions', [{}])[0].get('snippet', 'No Snippet'),
                "opinions": result.get('opinions', [])
            }
            formatted_results["results"].append(case_data)

        return formatted_results

    def save_json_to_file(self, data, search_term):
        filename = re.sub(r'[^a-zA-Z0-9_]', '_', search_term) + "_results.txt"
        
        with open(filename, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        print(f"Data saved to {filename}")

    def ip_lookup(self, ip, api_key):
        try:
            url = f"https://ipinfo.io/{ip}/json?token={api_key}"
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error performing IP lookup: {e}")
            return None

def print_ascii_art():
    ascii_art = '''
     _____     ____   __
    |_ _\\ \\   / /\\ \\ / /
     | | \\ \\ / /  \\ V /
     | |  \\ V /    | |
    |___|  \\_/     |_|
    '''
    print(Fore.GREEN + ascii_art)
    print(Fore.GREEN + "Ivy Spread")

def menu():
    print_ascii_art()
    print(Fore.BLUE + "\nIvy Spread Menu:")
    print(Fore.BLUE + "1. Perform ID Search")
    print(Fore.BLUE + "2. Export Accounts")
    print(Fore.BLUE + "3. Terminate Search")
    print(Fore.BLUE + "4. Search CourtListener")
    print(Fore.BLUE + "5. IP Lookup")
    print(Fore.BLUE + "6. Exit")

    choice = input(Fore.BLUE + "Choose an option: ")

    identity_service = IdentityService(api_key="2591bf36-50e1-4930-918e-6b34f0295f80")  # Your actual IntelX API key

    if choice == '1':
        term = input("Enter search term: ")
        maxresults = int(input("Enter maximum results: "))
        buckets = input("Enter buckets (optional): ")
        results = identity_service.idsearch(term, maxresults=maxresults, buckets=buckets)
        print(json.dumps(results, indent=4))  # Print results in JSON format
        identity_service.save_json_to_file(results, term)  # Save to file based on search term

    elif choice == '2':
        term = input("Enter term to export accounts: ")
        maxresults = int(input("Enter maximum results: "))
        datefrom = input("Enter start date (YYYY-MM-DD HH:MM:SS) or leave empty: ")
        dateto = input("Enter end date (YYYY-MM-DD HH:MM:SS) or leave empty: ")
        buckets = input("Enter buckets (optional): ")
        exported_data = identity_service.idsearch(term, maxresults=maxresults, datefrom=datefrom, dateto=dateto, buckets=buckets)
        identity_service.save_json_to_file(exported_data, term)

    elif choice == '3':
        search_id = input("Enter search ID to terminate: ")
        identity_service.terminate_search(search_id)

    elif choice == '4':
        query = input("Enter query for CourtListener search: ")
        results = identity_service.search_courtlistener(query)
        formatted_results = identity_service.display_courtlistener_results(results)
        print(json.dumps(formatted_results, indent=4))

    elif choice == '5':
        ip_address = input("Enter IP address to lookup: ")
        ip_info = identity_service.ip_lookup(ip_address, "179ebb9875a9b2")  # Using the provided API key
        print(json.dumps(ip_info, indent=4))

    elif choice == '6':
        print(Fore.GREEN + "Exiting Ivy Spread.")
        exit()
    else:
        print(Fore.RED + "Invalid choice, please try again.")

if __name__ == "__main__":
    while True:
        menu()