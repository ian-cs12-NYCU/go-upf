import requests
import time
import json

def health_check():
    url = "http://127.0.0.8:8000/nwdaf-oam/"
    try:
        print(f"------------------- Health Check UPF SBI server: {url} ---------------------------")
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print("Status Code:", response.status_code)
            print("Headers:", response.headers)
            print("Body:", response.text)
            print("✅ Health Check Passed ")
        else:
            print(f"UPF Health Check Failed: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

def test_packet_counter_api(iteration=3, interval=2):
    """
    Test the Packet Counter API.
    interval unit: s
    """
    url = "http://127.0.0.8:8000/nwdaf-oam/packets-count"
    for i in range(iteration):
        try:
            print(f"------------------- Test Packet Counter API (Iteration {i+1}): {url} ---------------------------")
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                print("Status Code:", response.status_code)
                print("Headers:", response.headers)
                print("Body:", json.dumps(data, indent=2))
                print("✅ Test Passed ")
            else:
                print(f"Test Failed: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
        if i < iteration - 1:
            time.sleep(interval)

if __name__ == "__main__":
    health_check()
    test_packet_counter_api()