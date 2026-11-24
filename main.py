import requests, argparse
from sys import exit
from scanner import scan 
from templates import generate

#taking the arguments from the cmd line
parsing  = argparse.ArgumentParser()
parsing.add_argument("--target", type=str, required=True)
args = parsing.parse_args()
print("=====HTTP Security Header Auditing Tool launched=====")
print("In a moment, please wait...")

session = requests.Session()
session.max_redirects = 10
h = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}
try:
    response = session.get(
    args.target,
    headers= h,
    allow_redirects= True,
    timeout= 20 
    )
except requests.exceptions.TooManyRedirects as e1:
    print(f"[DEBUG] error during request, too many redirects : {e1}!")
    exit(1)
except requests.exceptions.RequestException as e:
    print(f"[DEBUG] error during request, Check your internet Connection : {e}!")
    exit(1)

result = {
    "url" : args.target,
    "final_url" : response.url,
    "status" : response.status_code,
    "headers" : dict(response.headers),
    "body" : response.text
}
sec_headers = {k.lower(): v.lower() for k, v in result["headers"].items()}
    
if result["status"] == 200:
    print("\n")
    print(f"Initial URL :{args.target}")
    print(f"URL final : {result['final_url']}")
    print("\n")
    print("======================")
    print("Evaluation Summary :")
    print("======================")
    print("\n")
    r = scan.evalution_orchester(sec_headers)
    r["Target"] = result["url"]
    r["Time"] = response.headers.get("Date")
    print(f"Target : {r['Target']}")
    print(f"Time : {r['Time']}")
    print(f"Global Score : {r['Score']}")
    print(f"Level : {r['Level']}")
    generate.generator(r)
else :
    print(result["status"])