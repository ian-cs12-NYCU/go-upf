import requests
import time
import json
import sys

BASE_URL = "http://127.0.0.8:8000/nwdaf-oam"

def print_banner(title):
    """Print a formatted banner for test sections"""
    print("\n" + "="*80)
    print(f" {title}")
    print("="*80)

def print_response(response, test_name):
    """Print formatted response information"""
    print(f"\n🧪 {test_name}")
    print(f"📡 URL: {response.url}")
    print(f"📊 Status Code: {response.status_code}")
    print(f"📋 Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
    
    if response.status_code == 200:
        try:
            # Try to parse as JSON first
            data = response.json()
            print(f"📄 Response Body (JSON):")
            print(json.dumps(data, indent=2, ensure_ascii=False))
            print("✅ Test Passed")
        except json.JSONDecodeError:
            # If not JSON, print as plain text
            print(f"📄 Response Body (Text): {response.text}")
            print("✅ Test Passed (Non-JSON response)")
    else:
        print(f"❌ Test Failed: {response.status_code}")
        print(f"📄 Error Body: {response.text}")
    
    print(f"⏱️  Response Time: {response.elapsed.total_seconds():.3f}s")

def health_check():
    """Health check for UPF SBI server"""
    print_banner("Health Check")
    url = f"{BASE_URL}/"
    try:
        response = requests.get(url, timeout=5)
        print(f"\n🧪 UPF SBI Server Health Check")
        print(f"📡 URL: {response.url}")
        print(f"📊 Status Code: {response.status_code}")
        
        if response.status_code == 200:
            # Health check endpoint returns plain text, not JSON
            print(f"📄 Response Body: {response.text}")
            print("✅ Health Check Passed")
            return True
        else:
            print(f"❌ Health Check Failed: {response.status_code}")
            print(f"📄 Error Body: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Health Check Failed: {e}")
        return False

def test_flow_statistics_all():
    """Test GET /nwdaf-oam/flows/statistics - Get all flow statistics"""
    url = f"{BASE_URL}/flows/statistics"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Flow Statistics (All Flows)")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_flow_statistics_specific():
    """Test GET /nwdaf-oam/flows/statistics/{srcIP}/{dstIP}/{srcPort}/{dstPort}"""
    print("\n📝 Enter flow parameters for specific flow statistics:")
    src_ip = input("Source IP (e.g., 192.168.1.1): ").strip()
    dst_ip = input("Destination IP (e.g., 192.168.1.100): ").strip()
    src_port = input("Source Port (e.g., 80): ").strip()
    dst_port = input("Destination Port (e.g., 8080): ").strip()
    
    if not all([src_ip, dst_ip, src_port, dst_port]):
        print("❌ All parameters are required!")
        return
    
    url = f"{BASE_URL}/flows/statistics/{src_ip}/{dst_ip}/{src_port}/{dst_port}"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, f"Flow Statistics ({src_ip}:{src_port} -> {dst_ip}:{dst_port})")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_packet_records_all():
    """Test GET /nwdaf-oam/flows/packet-records - Get packet records for all flows"""
    url = f"{BASE_URL}/flows/packet-records"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Packet Records (All Flows)")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_packet_records_specific():
    """Test GET /nwdaf-oam/flows/packet-records/{srcIP}/{dstIP}/{srcPort}/{dstPort}"""
    print("\n📝 Enter flow parameters for specific packet records:")
    src_ip = input("Source IP (e.g., 192.168.1.1): ").strip()
    dst_ip = input("Destination IP (e.g., 192.168.1.100): ").strip()
    src_port = input("Source Port (e.g., 80): ").strip()
    dst_port = input("Destination Port (e.g., 8080): ").strip()
    
    if not all([src_ip, dst_ip, src_port, dst_port]):
        print("❌ All parameters are required!")
        return
    
    url = f"{BASE_URL}/flows/packet-records/{src_ip}/{dst_ip}/{src_port}/{dst_port}"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, f"Packet Records ({src_ip}:{src_port} -> {dst_ip}:{dst_port})")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_flow_count():
    """Test GET /nwdaf-oam/flows/count - Get total flow count"""
    url = f"{BASE_URL}/flows/count"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Flow Count")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_packets_count():
    """Test GET /nwdaf-oam/packets-count - Combined flow data (legacy API)"""
    url = f"{BASE_URL}/packets-count"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Packets Count (Combined Flow Data)")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_source_ips_all():
    """Test GET /nwdaf-oam/source-ips - Get all source IPs"""
    url = f"{BASE_URL}/source-ips"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Source IPs (All)")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_source_ip_specific():
    """Test GET /nwdaf-oam/source-ips/{ip} - Get specific source IP"""
    ip = input("\n📝 Enter Source IP (e.g., 192.168.1.1): ").strip()
    if not ip:
        print("❌ IP address is required!")
        return
    
    url = f"{BASE_URL}/source-ips/{ip}"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, f"Source IP ({ip})")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_source_ips_count():
    """Test GET /nwdaf-oam/source-ips/count - Get source IPs count"""
    url = f"{BASE_URL}/source-ips/count"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Source IPs Count")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_source_ips_top():
    """Test GET /nwdaf-oam/source-ips/top - Get top source IPs"""
    url = f"{BASE_URL}/source-ips/top"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Top Source IPs")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_source_ips_stats():
    """Test GET /nwdaf-oam/source-ips/stats - Get source IPs statistics"""
    url = f"{BASE_URL}/source-ips/stats"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Source IPs Statistics")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_source_ips_clear():
    """Test DELETE /nwdaf-oam/source-ips - Clear source IPs"""
    confirm = input("\n⚠️  This will clear all source IP data. Continue? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ Operation cancelled")
        return
    
    url = f"{BASE_URL}/source-ips"
    try:
        response = requests.delete(url, timeout=10)
        print_response(response, "Clear Source IPs")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_nf_resource():
    """Test GET /nwdaf-oam/nf-resource - Get NF resource information"""
    url = f"{BASE_URL}/nf-resource"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "NF Resource")
    except Exception as e:
        print(f"❌ Error: {e}")

def continuous_monitoring():
    """Continuous monitoring mode"""
    print_banner("Continuous Monitoring Mode")
    print("Available APIs for monitoring:")
    print("1. Flow Statistics (All)")
    print("2. Flow Count")
    print("3. Packets Count (Combined)")
    print("4. Source IPs Count")
    print("5. Source IPs Stats")
    
    choice = input("\nSelect API to monitor (1-5): ").strip()
    interval = input("Monitoring interval in seconds (default: 5): ").strip()
    
    try:
        interval = int(interval) if interval else 5
    except ValueError:
        interval = 5
    
    api_map = {
        '1': (f"{BASE_URL}/flows/statistics", "Flow Statistics"),
        '2': (f"{BASE_URL}/flows/count", "Flow Count"),
        '3': (f"{BASE_URL}/packets-count", "Packets Count"),
        '4': (f"{BASE_URL}/source-ips/count", "Source IPs Count"),
        '5': (f"{BASE_URL}/source-ips/stats", "Source IPs Stats")
    }
    
    if choice not in api_map:
        print("❌ Invalid choice!")
        return
    
    url, name = api_map[choice]
    print(f"\n🔄 Starting continuous monitoring of {name}")
    print(f"📊 Interval: {interval} seconds")
    print("Press Ctrl+C to stop\n")
    
    try:
        iteration = 1
        while True:
            print(f"\n--- Iteration {iteration} ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---")
            try:
                response = requests.get(url, timeout=10)
                print_response(response, f"{name} (Monitoring)")
            except Exception as e:
                print(f"❌ Error: {e}")
            
            iteration += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n🛑 Monitoring stopped by user")

def run_all_tests():
    """Run all available tests"""
    print_banner("Running All Tests")
    
    test_functions = [
        ("Health Check", health_check),
        ("NF Resource", test_nf_resource),
        ("Flow Statistics (All)", test_flow_statistics_all),
        ("Flow Count", test_flow_count),
        ("Packet Records (All)", test_packet_records_all),
        ("Packets Count (Combined)", test_packets_count),
        ("Source IPs (All)", test_source_ips_all),
        ("Source IPs Count", test_source_ips_count),
        ("Source IPs Top", test_source_ips_top),
        ("Source IPs Stats", test_source_ips_stats)
    ]
    
    for test_name, test_func in test_functions:
        print_banner(f"Running: {test_name}")
        test_func()
        time.sleep(1)  # Small delay between tests

def show_menu():
    """Display the main menu"""
    print("\n" + "="*60)
    print("🚀 UPF eBPF Flow Analytics API Test Suite")
    print("="*60)
    print("\n📋 Available Tests:")
    print("\n🔍 Flow Analytics APIs:")
    print("  1.  Flow Statistics (All Flows)")
    print("  2.  Flow Statistics (Specific Flow)")
    print("  3.  Packet Records (All Flows)")
    print("  4.  Packet Records (Specific Flow)")
    print("  5.  Flow Count")
    print("  6.  Packets Count (Combined/Legacy)")
    
    print("\n📊 Source IP Analytics APIs:")
    print("  7.  Source IPs (All)")
    print("  8.  Source IP (Specific)")
    print("  9.  Source IPs Count")
    print("  10. Source IPs Top")
    print("  11. Source IPs Statistics")
    print("  12. Clear Source IPs")
    
    print("\n⚙️  System APIs:")
    print("  13. Health Check")
    print("  14. NF Resource")
    
    print("\n🛠️  Utilities:")
    print("  15. Continuous Monitoring")
    print("  16. Run All Tests")
    print("  0.  Exit")
    
    print("\n" + "="*60)

def main():
    """Main function"""
    while True:
        show_menu()
        choice = input("\n🎯 Select an option (0-16): ").strip()
        
        if choice == '0':
            print("\n👋 Goodbye!")
            sys.exit(0)
        elif choice == '1':
            print_banner("Flow Statistics (All Flows)")
            test_flow_statistics_all()
        elif choice == '2':
            print_banner("Flow Statistics (Specific Flow)")
            test_flow_statistics_specific()
        elif choice == '3':
            print_banner("Packet Records (All Flows)")
            test_packet_records_all()
        elif choice == '4':
            print_banner("Packet Records (Specific Flow)")
            test_packet_records_specific()
        elif choice == '5':
            print_banner("Flow Count")
            test_flow_count()
        elif choice == '6':
            print_banner("Packets Count (Combined/Legacy)")
            test_packets_count()
        elif choice == '7':
            print_banner("Source IPs (All)")
            test_source_ips_all()
        elif choice == '8':
            print_banner("Source IP (Specific)")
            test_source_ip_specific()
        elif choice == '9':
            print_banner("Source IPs Count")
            test_source_ips_count()
        elif choice == '10':
            print_banner("Source IPs Top")
            test_source_ips_top()
        elif choice == '11':
            print_banner("Source IPs Statistics")
            test_source_ips_stats()
        elif choice == '12':
            print_banner("Clear Source IPs")
            test_source_ips_clear()
        elif choice == '13':
            print_banner("Health Check")
            health_check()
        elif choice == '14':
            print_banner("NF Resource")
            test_nf_resource()
        elif choice == '15':
            continuous_monitoring()
        elif choice == '16':
            run_all_tests()
        else:
            print("❌ Invalid choice! Please select 0-16.")
        
        input("\n📱 Press Enter to continue...")

if __name__ == "__main__":
    main()