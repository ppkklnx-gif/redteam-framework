"""
Test suite for Red Team Framework v3.1 - Major Upgrade Features
Tests: Adaptive orchestration, credential vault, conditional chains, 
       auto-trigger chains, session manager, dynamic tool catalog, 
       attack timeline, abort scan
"""
import pytest
import requests
import time
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestHealthAndBasics:
    """Basic health checks"""
    
    def test_api_health(self):
        """Test API is running"""
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data or "status" in data
        print(f"✓ API health check passed: {data}")

    def test_mitre_tactics(self):
        """Test MITRE tactics endpoint"""
        response = requests.get(f"{BASE_URL}/api/mitre/tactics")
        assert response.status_code == 200
        data = response.json()
        assert "tactics" in data
        print(f"✓ MITRE tactics: {len(data['tactics'])} tactics loaded")


class TestDynamicToolCatalog:
    """Test dynamic tool add/remove via API (Point 6)"""
    
    def test_add_custom_tool(self):
        """POST /api/tools/add - adds custom tool to catalog"""
        tool_data = {
            "id": "test_custom_tool",
            "cmd": "echo {target}",
            "phase": "reconnaissance",
            "desc": "Test custom tool for testing"
        }
        response = requests.post(f"{BASE_URL}/api/tools/add", json=tool_data)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "added"
        assert "tool" in data
        assert data["tool"]["cmd"] == "echo {target}"
        print(f"✓ Custom tool added: {data}")
    
    def test_verify_tool_in_catalog(self):
        """Verify added tool appears in tools list"""
        response = requests.get(f"{BASE_URL}/api/tools")
        assert response.status_code == 200
        data = response.json()
        assert "tools" in data
        # Check if our custom tool is in the list
        tool_ids = list(data["tools"].keys())
        assert "test_custom_tool" in tool_ids, f"Custom tool not found in: {tool_ids}"
        print(f"✓ Custom tool verified in catalog")
    
    def test_remove_custom_tool(self):
        """DELETE /api/tools/{id} - removes custom tool"""
        response = requests.delete(f"{BASE_URL}/api/tools/test_custom_tool")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "removed"
        print(f"✓ Custom tool removed: {data}")
    
    def test_remove_nonexistent_tool(self):
        """DELETE /api/tools/{id} - returns 404 for nonexistent tool"""
        response = requests.delete(f"{BASE_URL}/api/tools/nonexistent_tool_xyz")
        assert response.status_code == 404
        print(f"✓ Nonexistent tool returns 404 as expected")


class TestCustomMsfModules:
    """Test custom Metasploit module addition"""
    
    def test_add_custom_msf_module(self):
        """POST /api/metasploit/modules/add - adds custom MSF module"""
        module_data = {
            "name": "exploit/test/custom_module",
            "desc": "Test custom module",
            "rank": "normal",
            "category": "exploit",
            "mitre": "T1190"
        }
        response = requests.post(f"{BASE_URL}/api/metasploit/modules/add", json=module_data)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "added"
        assert data["module"]["name"] == "exploit/test/custom_module"
        print(f"✓ Custom MSF module added: {data}")
    
    def test_verify_msf_module_in_list(self):
        """Verify custom module appears in modules list"""
        response = requests.get(f"{BASE_URL}/api/metasploit/modules")
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data
        module_names = [m["name"] for m in data["modules"]]
        assert "exploit/test/custom_module" in module_names, f"Custom module not found"
        print(f"✓ Custom MSF module verified in list")


class TestAdaptiveScanAndTimeline:
    """Test adaptive scan with timeline, vault, and sessions endpoints"""
    
    @pytest.fixture(scope="class")
    def scan_id(self):
        """Start a scan and return its ID"""
        scan_data = {
            "target": "10.10.10.1",
            "scan_phases": ["reconnaissance"],
            "tools": []
        }
        response = requests.post(f"{BASE_URL}/api/scan/start", json=scan_data)
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        print(f"✓ Scan started: {data['scan_id']}")
        return data["scan_id"]
    
    def test_scan_start(self, scan_id):
        """POST /api/scan/start - starts adaptive scan"""
        assert scan_id is not None
        print(f"✓ Scan ID obtained: {scan_id}")
    
    def test_scan_status_has_adaptive_fields(self, scan_id):
        """GET /api/scan/{id}/status - returns vault_summary, timeline, adaptive_log"""
        # Wait for scan to progress
        time.sleep(3)
        
        response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
        assert response.status_code == 200
        data = response.json()
        
        # Check required fields exist
        assert "status" in data
        assert "progress" in data
        assert "vault_summary" in data, f"Missing vault_summary in: {list(data.keys())}"
        assert "timeline" in data, f"Missing timeline in: {list(data.keys())}"
        assert "adaptive_log" in data, f"Missing adaptive_log in: {list(data.keys())}"
        
        print(f"✓ Scan status has adaptive fields: status={data['status']}, progress={data['progress']}")
        print(f"  vault_summary: {data['vault_summary']}")
        print(f"  timeline entries: {len(data['timeline'])}")
        print(f"  adaptive_log entries: {len(data['adaptive_log'])}")
    
    def test_scan_timeline_endpoint(self, scan_id):
        """GET /api/scan/{id}/timeline - returns chronological attack timeline"""
        response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/timeline")
        assert response.status_code == 200
        data = response.json()
        
        assert "timeline" in data
        assert "adaptive_log" in data
        assert isinstance(data["timeline"], list)
        assert isinstance(data["adaptive_log"], list)
        
        print(f"✓ Timeline endpoint works: {len(data['timeline'])} events, {len(data['adaptive_log'])} adaptive decisions")
    
    def test_scan_vault_endpoint(self, scan_id):
        """GET /api/scan/{id}/vault - returns credential vault contents"""
        response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/vault")
        assert response.status_code == 200
        data = response.json()
        
        # Vault should have summary fields
        assert "total_credentials" in data or "credentials" in data
        print(f"✓ Vault endpoint works: {data}")
    
    def test_scan_sessions_endpoint(self, scan_id):
        """GET /api/scan/{id}/sessions - returns session list and post_exploit_actions"""
        response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/sessions")
        assert response.status_code == 200
        data = response.json()
        
        assert "sessions" in data
        assert "post_exploit_actions" in data
        assert isinstance(data["sessions"], list)
        assert isinstance(data["post_exploit_actions"], list)
        
        print(f"✓ Sessions endpoint works: {len(data['sessions'])} sessions, {len(data['post_exploit_actions'])} post-exploit actions")


class TestScanCompletion:
    """Test scan completes with timeline events"""
    
    def test_scan_completes_with_timeline(self):
        """Scan completes with timeline showing tool_start and tool_complete events"""
        # Start a scan
        scan_data = {
            "target": "10.10.10.2",
            "scan_phases": ["reconnaissance"],
            "tools": []
        }
        response = requests.post(f"{BASE_URL}/api/scan/start", json=scan_data)
        assert response.status_code == 200
        scan_id = response.json()["scan_id"]
        
        # Wait for completion (max 30 seconds)
        max_wait = 30
        start_time = time.time()
        completed = False
        final_data = None
        
        while time.time() - start_time < max_wait:
            response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
            data = response.json()
            if data["status"] in ["completed", "error", "aborted"]:
                completed = True
                final_data = data
                break
            time.sleep(2)
        
        assert completed, f"Scan did not complete within {max_wait}s"
        assert final_data["status"] == "completed", f"Scan status: {final_data['status']}"
        
        # Check timeline has tool_start and tool_complete events
        timeline = final_data.get("timeline", [])
        event_types = [e.get("type") for e in timeline]
        
        assert "start" in event_types, f"Missing 'start' event in timeline: {event_types}"
        assert "tool_start" in event_types or "tool_complete" in event_types, f"Missing tool events in timeline: {event_types}"
        
        print(f"✓ Scan completed with timeline events: {event_types}")
        print(f"  vault_summary: {final_data.get('vault_summary', {})}")


class TestAbortScan:
    """Test abort scan functionality"""
    
    def test_abort_running_scan(self):
        """POST /api/scan/{id}/abort - aborts running scan"""
        # Start a scan
        scan_data = {
            "target": "10.10.10.3",
            "scan_phases": ["reconnaissance", "initial_access"],
            "tools": []
        }
        response = requests.post(f"{BASE_URL}/api/scan/start", json=scan_data)
        assert response.status_code == 200
        scan_id = response.json()["scan_id"]
        
        # Wait a moment for scan to start
        time.sleep(1)
        
        # Abort the scan
        response = requests.post(f"{BASE_URL}/api/scan/{scan_id}/abort")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "aborted"
        assert data["scan_id"] == scan_id
        
        print(f"✓ Scan aborted successfully: {data}")
        
        # Verify scan status is aborted
        time.sleep(1)
        response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
        data = response.json()
        assert data["status"] == "aborted", f"Expected aborted, got: {data['status']}"
        print(f"✓ Scan status confirmed aborted")
    
    def test_abort_nonrunning_scan(self):
        """POST /api/scan/{id}/abort - returns 400 for non-running scan"""
        response = requests.post(f"{BASE_URL}/api/scan/nonexistent_scan_xyz/abort")
        assert response.status_code == 400
        print(f"✓ Abort non-running scan returns 400 as expected")


class TestAttackChains:
    """Test attack chain endpoints"""
    
    def test_get_chains(self):
        """GET /api/chains - returns attack chains"""
        response = requests.get(f"{BASE_URL}/api/chains")
        assert response.status_code == 200
        data = response.json()
        assert "chains" in data
        assert len(data["chains"]) > 0
        print(f"✓ Attack chains: {len(data['chains'])} chains available")
        for chain in data["chains"][:3]:
            print(f"  - {chain.get('id', chain.get('name', 'unknown'))}")
    
    def test_get_chain_details(self):
        """GET /api/chains/{id} - returns chain details"""
        # First get list of chains
        response = requests.get(f"{BASE_URL}/api/chains")
        chains = response.json()["chains"]
        
        if chains:
            chain_id = chains[0].get("id", "web_to_shell")
            response = requests.get(f"{BASE_URL}/api/chains/{chain_id}")
            assert response.status_code == 200
            data = response.json()
            assert "name" in data or "steps" in data
            print(f"✓ Chain details for {chain_id}: {data.get('name', 'N/A')}")


class TestTacticalDecisions:
    """Test tactical decision engine endpoints"""
    
    def test_service_attacks(self):
        """GET /api/tactical/service-attacks - returns service attack strategies"""
        response = requests.get(f"{BASE_URL}/api/tactical/service-attacks")
        assert response.status_code == 200
        data = response.json()
        assert "strategies" in data
        print(f"✓ Service attack strategies: {len(data['strategies'])} services")
    
    def test_vuln_exploits(self):
        """GET /api/tactical/vuln-exploits - returns vulnerability exploit mappings"""
        response = requests.get(f"{BASE_URL}/api/tactical/vuln-exploits")
        assert response.status_code == 200
        data = response.json()
        assert "mappings" in data or "exploits" in data
        mappings = data.get("mappings", data.get("exploits", {}))
        print(f"✓ Vulnerability exploits: {len(mappings)} mappings")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
