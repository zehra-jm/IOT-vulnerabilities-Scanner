from vulners import Vulners

API_KEY = "your API key"
vulners = Vulners(api_key=API_KEY)

def lookup_cves(service_name):
    try:
        results = vulners.search(f"{service_name}")
        print(results)  # line to inspect the structure
        cve_list = []
        for result in results:
            if 'cvelist' in result:
                for cve in result['cvelist']:
                    cve_list.append(cve)
            if len(cve_list) >= 5:
                break
        return cve_list
    except Exception as e:
        print(f"Error looking up CVEs for {service_name}: {e}")
        return []
