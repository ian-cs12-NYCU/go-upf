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

def test_sampling_config_get():
    """Test GET /nwdaf-oam/sampling-config - Get current sampling configuration"""
    url = f"{BASE_URL}/sampling-config"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Sampling Configuration (Get)")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_sampling_config_update_json():
    """Test PUT /nwdaf-oam/sampling-config - Update sampling configuration via JSON"""
    sample_rate = input("\n📝 Enter new sample rate (e.g., 100): ").strip()
    
    try:
        sample_rate = int(sample_rate)
    except ValueError:
        print("❌ Invalid sample rate! Must be a number.")
        return
    
    if sample_rate <= 0:
        print("❌ Sample rate must be greater than 0!")
        return
    
    url = f"{BASE_URL}/sampling-config"
    data = {"sample_rate": sample_rate}
    
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, f"Sampling Configuration Update (JSON) - Rate: {sample_rate}")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_sampling_config_update_param():
    """Test PUT /nwdaf-oam/sampling-config/{rate} - Update sampling configuration via URL parameter"""
    sample_rate = input("\n📝 Enter new sample rate (e.g., 50): ").strip()
    
    try:
        sample_rate = int(sample_rate)
    except ValueError:
        print("❌ Invalid sample rate! Must be a number.")
        return
    
    if sample_rate <= 0:
        print("❌ Sample rate must be greater than 0!")
        return
    
    url = f"{BASE_URL}/sampling-config/{sample_rate}"
    
    try:
        response = requests.put(url, timeout=10)
        print_response(response, f"Sampling Configuration Update (URL Param) - Rate: {sample_rate}")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_sampling_config_workflow():
    """Test complete sampling configuration workflow"""
    print_banner("Sampling Configuration Workflow Test")
    
    # Step 1: Get current configuration
    print("\n🔍 Step 1: Getting current sampling configuration...")
    url = f"{BASE_URL}/sampling-config"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Current Sampling Configuration")
        
        if response.status_code == 200:
            current_config = response.json()
            current_rate = current_config.get('sample_rate', 1)
            print(f"📊 Current sample rate: {current_rate}")
        else:
            print("❌ Failed to get current configuration")
            return
    except Exception as e:
        print(f"❌ Error getting current config: {e}")
        return
    
    # Step 2: Update via JSON
    new_rate_1 = current_rate * 2 if current_rate < 500 else 100
    print(f"\n🔄 Step 2: Updating sample rate to {new_rate_1} via JSON...")
    data = {"sample_rate": new_rate_1}
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, f"Update via JSON - Rate: {new_rate_1}")
    except Exception as e:
        print(f"❌ Error updating via JSON: {e}")
        return
    
    time.sleep(1)
    
    # Step 3: Verify the update
    print(f"\n✅ Step 3: Verifying update...")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            updated_config = response.json()
            updated_rate = updated_config.get('sample_rate', 0)
            if updated_rate == new_rate_1:
                print(f"✅ Verification successful! Sample rate is now: {updated_rate}")
            else:
                print(f"❌ Verification failed! Expected: {new_rate_1}, Got: {updated_rate}")
        else:
            print("❌ Failed to verify update")
    except Exception as e:
        print(f"❌ Error verifying update: {e}")
    
    time.sleep(1)
    
    # Step 4: Update via URL parameter
    new_rate_2 = new_rate_1 // 2 if new_rate_1 > 1 else 25
    print(f"\n🔄 Step 4: Updating sample rate to {new_rate_2} via URL parameter...")
    url_param = f"{BASE_URL}/sampling-config/{new_rate_2}"
    try:
        response = requests.put(url_param, timeout=10)
        print_response(response, f"Update via URL Parameter - Rate: {new_rate_2}")
    except Exception as e:
        print(f"❌ Error updating via URL parameter: {e}")
        return
    
    time.sleep(1)
    
    # Step 5: Final verification
    print(f"\n✅ Step 5: Final verification...")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            final_config = response.json()
            final_rate = final_config.get('sample_rate', 0)
            if final_rate == new_rate_2:
                print(f"✅ Final verification successful! Sample rate is now: {final_rate}")
                print("🎉 Sampling configuration workflow test completed successfully!")
            else:
                print(f"❌ Final verification failed! Expected: {new_rate_2}, Got: {final_rate}")
        else:
            print("❌ Failed to perform final verification")
    except Exception as e:
        print(f"❌ Error in final verification: {e}")

def test_sampling_config_error_cases():
    """Test sampling configuration error cases"""
    print_banner("Sampling Configuration Error Cases Test")
    
    # Test 1: Invalid sample rate (0)
    print("\n🧪 Test 1: Invalid sample rate (0)")
    url = f"{BASE_URL}/sampling-config"
    data = {"sample_rate": 0}
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, "Invalid Sample Rate (0)")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Test 2: Invalid sample rate (negative)
    print("\n🧪 Test 2: Invalid sample rate (-10)")
    data = {"sample_rate": -10}
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, "Invalid Sample Rate (-10)")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Test 3: Invalid JSON format
    print("\n🧪 Test 3: Invalid JSON format")
    try:
        response = requests.put(url, data="invalid json", 
                              headers={'Content-Type': 'application/json'}, timeout=10)
        print_response(response, "Invalid JSON Format")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Test 4: Very large sample rate
    print("\n🧪 Test 4: Very large sample rate (2000000)")
    data = {"sample_rate": 2000000}
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, "Very Large Sample Rate (2000000)")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Test 5: Invalid URL parameter
    print("\n🧪 Test 5: Invalid URL parameter (non-numeric)")
    url_invalid = f"{BASE_URL}/sampling-config/invalid"
    try:
        response = requests.put(url_invalid, timeout=10)
        print_response(response, "Invalid URL Parameter (non-numeric)")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_k_config_get():
    """Test GET /nwdaf-oam/defaultK - Get current global default K"""
    url = f"{BASE_URL}/defaultK"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Global Default K (Get)")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_k_config_update_global():
    """Test PUT /nwdaf-oam/defaultK - Update global default K"""
    default_k = input("\n📝 Enter new global default K value (e.g., 32): ").strip()
    
    try:
        default_k = int(default_k)
    except ValueError:
        print("❌ Invalid K value! Must be a number.")
        return
    
    if default_k <= 0:
        print("❌ K value must be greater than 0!")
        return
    
    # Ask if user wants to update existing flows
    update_existing = input("📝 Update existing flows? (y/N): ").strip().lower() == 'y'
    
    url = f"{BASE_URL}/defaultK"
    data = {
        "defaultK": default_k,
        "updateExistingFlows": update_existing
    }
    
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, f"Global Default K Update - K: {default_k}, Update Existing: {update_existing}")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_k_config_update_specific_flow():
    """Test PUT /nwdaf-oam/flows/{srcIP}/{srcPort}/{dstIP}/{dstPort}/{protocol}/k - Update K for specific flow"""
    print("\n📝 Enter flow parameters for specific K update:")
    src_ip = input("Source IP (e.g., 192.168.1.1): ").strip()
    src_port = input("Source Port (e.g., 80): ").strip()
    dst_ip = input("Destination IP (e.g., 192.168.1.100): ").strip()
    dst_port = input("Destination Port (e.g., 8080): ").strip()
    protocol = input("Protocol (e.g., 6 for TCP, 17 for UDP): ").strip()
    k_value = input("New K value (e.g., 64): ").strip()
    
    if not all([src_ip, src_port, dst_ip, dst_port, protocol, k_value]):
        print("❌ All parameters are required!")
        return
    
    try:
        src_port = int(src_port)
        dst_port = int(dst_port)
        protocol = int(protocol)
        k_value = int(k_value)
    except ValueError:
        print("❌ Invalid numeric values!")
        return
    
    if k_value <= 0:
        print("❌ K value must be greater than 0!")
        return
    
    url = f"{BASE_URL}/flows/{src_ip}/{src_port}/{dst_ip}/{dst_port}/{protocol}/k"
    data = {"k": k_value}
    
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, f"Specific Flow K Update ({src_ip}:{src_port} -> {dst_ip}:{dst_port}, Protocol: {protocol}, K: {k_value})")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_k_config_get_specific_flow():
    """Test GET /nwdaf-oam/flows/{srcIP}/{srcPort}/{dstIP}/{dstPort}/{protocol}/k - Get K for specific flow"""
    print("\n📝 Enter flow parameters to get specific K value:")
    src_ip = input("Source IP (e.g., 192.168.1.1): ").strip()
    src_port = input("Source Port (e.g., 80): ").strip()
    dst_ip = input("Destination IP (e.g., 192.168.1.100): ").strip()
    dst_port = input("Destination Port (e.g., 8080): ").strip()
    protocol = input("Protocol (e.g., 6 for TCP, 17 for UDP): ").strip()
    
    if not all([src_ip, src_port, dst_ip, dst_port, protocol]):
        print("❌ All parameters are required!")
        return
    
    try:
        src_port = int(src_port)
        dst_port = int(dst_port)
        protocol = int(protocol)
    except ValueError:
        print("❌ Invalid numeric values!")
        return
    
    url = f"{BASE_URL}/flows/{src_ip}/{src_port}/{dst_ip}/{dst_port}/{protocol}/k"
    
    try:
        response = requests.get(url, timeout=10)
        print_response(response, f"Specific Flow K Value ({src_ip}:{src_port} -> {dst_ip}:{dst_port}, Protocol: {protocol})")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_k_config_workflow():
    """Test complete K configuration workflow"""
    print_banner("K Configuration Workflow Test")
    
    # Step 1: Get current configuration
    print("\n🔍 Step 1: Getting current global default K...")
    url = f"{BASE_URL}/defaultK"
    try:
        response = requests.get(url, timeout=10)
        print_response(response, "Current Global Default K")
        
        if response.status_code == 200:
            current_config = response.json()
            current_k = current_config.get('defaultK', 16)
            print(f"📊 Current default K: {current_k}")
        else:
            print("❌ Failed to get current configuration")
            return
    except Exception as e:
        print(f"❌ Error getting current config: {e}")
        return
    
    # Step 2: Update global default K
    new_k = current_k * 2 if current_k < 32 else 8
    print(f"\n🔄 Step 2: Updating global default K to {new_k} (without updating existing flows)...")
    data = {
        "defaultK": new_k,
        "updateExistingFlows": False
    }
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, f"Update Global Default K - K: {new_k}")
    except Exception as e:
        print(f"❌ Error updating global K: {e}")
        return
    
    time.sleep(1)
    
    # Step 3: Verify the update
    print(f"\n✅ Step 3: Verifying global K update...")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            updated_config = response.json()
            updated_k = updated_config.get('defaultK', 0)
            if updated_k == new_k:
                print(f"✅ Verification successful! Default K is now: {updated_k}")
            else:
                print(f"❌ Verification failed! Expected: {new_k}, Got: {updated_k}")
        else:
            print("❌ Failed to verify update")
    except Exception as e:
        print(f"❌ Error verifying update: {e}")
    
    # Step 4: Test updating with existing flows
    new_k_2 = new_k // 2 if new_k > 1 else 24
    print(f"\n🔄 Step 4: Updating global default K to {new_k_2} (with updating existing flows)...")
    data = {
        "defaultK": new_k_2,
        "updateExistingFlows": True
    }
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, f"Update Global Default K with Existing Flows - K: {new_k_2}")
    except Exception as e:
        print(f"❌ Error updating global K with existing flows: {e}")
        return
    
    time.sleep(1)
    
    # Step 5: Final verification
    print(f"\n✅ Step 5: Final verification...")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            final_config = response.json()
            final_k = final_config.get('defaultK', 0)
            if final_k == new_k_2:
                print(f"✅ Final verification successful! Default K is now: {final_k}")
            else:
                print(f"❌ Final verification failed! Expected: {new_k_2}, Got: {final_k}")
        else:
            print("❌ Failed to perform final verification")
    except Exception as e:
        print(f"❌ Error in final verification: {e}")
    
    print("🎉 K configuration workflow test completed!")

def test_k_config_error_cases():
    """Test K configuration error cases"""
    print_banner("K Configuration Error Cases Test")
    
    # Test 1: Invalid K value (0)
    print("\n🧪 Test 1: Invalid global K value (0)")
    url = f"{BASE_URL}/defaultK"
    data = {"defaultK": 0, "updateExistingFlows": False}
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, "Invalid Global K Value (0)")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Test 2: Invalid K value (negative)
    print("\n🧪 Test 2: Invalid global K value (-5)")
    data = {"defaultK": -5, "updateExistingFlows": False}
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, "Invalid Global K Value (-5)")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Test 3: Very large K value
    print("\n🧪 Test 3: Very large K value (10000)")
    data = {"defaultK": 10000, "updateExistingFlows": False}
    try:
        response = requests.put(url, json=data, timeout=10)
        print_response(response, "Very Large K Value (10000)")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Test 4: Invalid flow data for specific flow K update
    print("\n🧪 Test 4: Invalid IP address for specific flow K update")
    url_flow = f"{BASE_URL}/flows/invalid-ip/80/192.168.1.100/8080/6/k"
    data = {"k": 32}
    try:
        response = requests.put(url_flow, json=data, timeout=10)
        print_response(response, "Invalid IP Address in Flow Path")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Test 5: Invalid port for specific flow K update
    print("\n🧪 Test 5: Invalid port for specific flow K update")
    url_flow = f"{BASE_URL}/flows/192.168.1.1/invalid-port/192.168.1.100/8080/6/k"
    data = {"k": 32}
    try:
        response = requests.put(url_flow, json=data, timeout=10)
        print_response(response, "Invalid Port in Flow Path")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Test 6: Missing JSON body for flow K update
    print("\n🧪 Test 6: Missing JSON body for flow K update")
    url_flow = f"{BASE_URL}/flows/192.168.1.1/80/192.168.1.100/8080/6/k"
    try:
        response = requests.put(url_flow, timeout=10)  # No JSON data
        print_response(response, "Missing JSON Body")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_k_config_performance():
    """Test K configuration performance with multiple flows"""
    print_banner("K Configuration Performance Test")
    
    # First get some flows to test with
    print("\n🔍 Step 1: Getting current flows...")
    flows_url = f"{BASE_URL}/flows/statistics"
    try:
        response = requests.get(flows_url, timeout=10)
        if response.status_code == 200:
            flows_data = response.json()
            flows = flows_data.get('flows', [])
            print(f"📊 Found {len(flows)} flows for testing")
            
            if len(flows) == 0:
                print("⚠️  No flows available for performance testing")
                return
        else:
            print("❌ Failed to get flows for testing")
            return
    except Exception as e:
        print(f"❌ Error getting flows: {e}")
        return
    
    # Test updating K for multiple flows
    print(f"\n🔄 Step 2: Testing K updates for up to 5 flows...")
    test_flows = flows[:5]  # Test with up to 5 flows
    
    url = f"{BASE_URL}/k-config/flow"
    success_count = 0
    failure_count = 0
    
    start_time = time.time()
    
    for i, flow in enumerate(test_flows):
        new_k = 64 + (i * 16)  # Different K values: 64, 80, 96, etc.
        
        data = {
            "flow_key": {
                "family": 4,
                "l4": 6,  # Assume TCP
                "src_ip": str(flow.get('srcIP', '127.0.0.1')),
                "dst_ip": str(flow.get('dstIP', '127.0.0.1')),
                "src_port": int(flow.get('srcPort', 80)),
                "dst_port": int(flow.get('dstPort', 8080))
            },
            "k": new_k
        }
        
        try:
            response = requests.put(url, json=data, timeout=10)
            if response.status_code == 200:
                success_count += 1
                print(f"✅ Flow {i+1}: K updated to {new_k}")
            else:
                failure_count += 1
                print(f"❌ Flow {i+1}: Failed to update K to {new_k}")
        except Exception as e:
            failure_count += 1
            print(f"❌ Flow {i+1}: Error - {e}")
        
        time.sleep(0.1)  # Small delay between requests
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print(f"\n📊 Performance Test Results:")
    print(f"   Total flows tested: {len(test_flows)}")
    print(f"   Successful updates: {success_count}")
    print(f"   Failed updates: {failure_count}")
    print(f"   Total time: {total_time:.3f} seconds")
    print(f"   Average time per update: {total_time/len(test_flows):.3f} seconds")

def continuous_k_monitoring():
    """Continuous monitoring of K configuration"""
    print_banner("Continuous K Configuration Monitoring")
    
    interval = input("Monitoring interval in seconds (default: 3): ").strip()
    try:
        interval = int(interval) if interval else 3
    except ValueError:
        interval = 3
    
    url = f"{BASE_URL}/defaultK"
    print(f"\n🔄 Starting continuous monitoring of K Configuration")
    print(f"📊 Interval: {interval} seconds")
    print("Press Ctrl+C to stop\n")
    
    try:
        iteration = 1
        last_k = None
        while True:
            print(f"\n--- Iteration {iteration} ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---")
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    config = response.json()
                    current_k = config.get('defaultK', 'Unknown')
                    enabled = config.get('enabled', False)
                    
                    if current_k != last_k:
                        print(f"🔄 Default K changed: {last_k} → {current_k}")
                        last_k = current_k
                    
                    print(f"📊 Current default K: {current_k}")
                    print(f"🔋 eBPF enabled: {enabled}")
                    print(f"⏱️  Response time: {response.elapsed.total_seconds():.3f}s")
                    print("✅ Status: OK")
                else:
                    print(f"❌ Error: HTTP {response.status_code}")
                    print(f"📄 Response: {response.text}")
            except Exception as e:
                print(f"❌ Error: {e}")
            
            iteration += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n🛑 Monitoring stopped by user")

def continuous_sampling_monitoring():
    """Continuous monitoring of sampling configuration"""
    print_banner("Continuous Sampling Configuration Monitoring")
    
    interval = input("Monitoring interval in seconds (default: 3): ").strip()
    try:
        interval = int(interval) if interval else 3
    except ValueError:
        interval = 3
    
    url = f"{BASE_URL}/sampling-config"
    print(f"\n🔄 Starting continuous monitoring of Sampling Configuration")
    print(f"📊 Interval: {interval} seconds")
    print("Press Ctrl+C to stop\n")
    
    try:
        iteration = 1
        last_rate = None
        while True:
            print(f"\n--- Iteration {iteration} ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---")
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    config = response.json()
                    current_rate = config.get('sample_rate', 'Unknown')
                    enabled = config.get('enabled', False)
                    
                    if current_rate != last_rate:
                        print(f"🔄 Sample rate changed: {last_rate} → {current_rate}")
                        last_rate = current_rate
                    
                    print(f"📊 Current sample rate: {current_rate}")
                    print(f"🔋 eBPF enabled: {enabled}")
                    print(f"⏱️  Response time: {response.elapsed.total_seconds():.3f}s")
                    print("✅ Status: OK")
                else:
                    print(f"❌ Error: HTTP {response.status_code}")
                    print(f"📄 Response: {response.text}")
            except Exception as e:
                print(f"❌ Error: {e}")
            
            iteration += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n🛑 Monitoring stopped by user")

def continuous_monitoring():
    """Continuous monitoring mode"""
    print_banner("Continuous Monitoring Mode")
    print("Available APIs for monitoring:")
    print("1. Flow Statistics (All)")
    print("2. Flow Count")
    print("3. Packets Count (Combined)")
    print("4. Source IPs Count")
    print("5. Source IPs Stats")
    print("6. Sampling Configuration")
    print("7. K Configuration")
    
    choice = input("\nSelect API to monitor (1-7): ").strip()
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
        '5': (f"{BASE_URL}/source-ips/stats", "Source IPs Stats"),
        '6': (f"{BASE_URL}/sampling-config", "Sampling Configuration"),
        '7': (f"{BASE_URL}/defaultK", "K Configuration")
    }
    
    if choice not in api_map:
        print("❌ Invalid choice!")
        return
    
    if choice == '6':
        continuous_sampling_monitoring()
        return
    elif choice == '7':
        continuous_k_monitoring()
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
        ("Sampling Configuration (Get)", test_sampling_config_get),
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
    
    print("\n🎛️  Sampling Configuration APIs:")
    print("  15. Get Sampling Configuration")
    print("  16. Update Sampling Configuration (JSON)")
    print("  17. Update Sampling Configuration (URL Param)")
    print("  18. Sampling Configuration Workflow Test")
    print("  19. Sampling Configuration Error Cases")
    
    print("\n� K Configuration APIs:")
    print("  20. Get K Configuration")
    print("  21. Update Global Default K")
    print("  22. Update Specific Flow K")
    print("  23. K Configuration Workflow Test")
    print("  24. K Configuration Error Cases")
    print("  25. K Configuration Performance Test")
    
    print("\n�🛠️  Utilities:")
    print("  26. Continuous Monitoring")
    print("  27. Run All Tests")
    print("  0.  Exit")
    
    print("\n" + "="*60)

def main():
    """Main function"""
    while True:
        show_menu()
        choice = input("\n🎯 Select an option (0-27): ").strip()
        
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
            print_banner("Get Sampling Configuration")
            test_sampling_config_get()
        elif choice == '16':
            print_banner("Update Sampling Configuration (JSON)")
            test_sampling_config_update_json()
        elif choice == '17':
            print_banner("Update Sampling Configuration (URL Param)")
            test_sampling_config_update_param()
        elif choice == '18':
            test_sampling_config_workflow()
        elif choice == '19':
            test_sampling_config_error_cases()
        elif choice == '20':
            print_banner("Get Global Default K")
            test_k_config_get()
        elif choice == '21':
            print_banner("Update Global Default K")
            test_k_config_update_global()
        elif choice == '22':
            print_banner("Get Specific Flow K")
            test_k_config_get_specific_flow()
        elif choice == '23':
            print_banner("Update Specific Flow K")
            test_k_config_update_specific_flow()
        elif choice == '24':
            test_k_config_workflow()
        elif choice == '25':
            test_k_config_error_cases()
        elif choice == '26':
            test_k_config_performance()
        elif choice == '27':
            continuous_monitoring()
        elif choice == '28':
            run_all_tests()
        else:
            print("❌ Invalid choice! Please select 0-27.")
        
        input("\n📱 Press Enter to continue...")

if __name__ == "__main__":
    main()