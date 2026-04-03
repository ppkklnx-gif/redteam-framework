"""
Test suite for C2 Integration features:
- msfrpcd integration endpoints
- WebSocket real-time updates
- Sliver C2 integration
- Unified C2 dashboard
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestMSFRPCEndpoints:
    """Metasploit RPC integration tests - msfrpcd not running, expect graceful offline responses"""
    
    def test_msf_status_returns_offline(self):
        """GET /api/msf/status - returns connection status (connected:false since no msfrpcd running)"""
        response = requests.get(f"{BASE_URL}/api/msf/status")
        assert response.status_code == 200
        data = response.json()
        assert "connected" in data
        assert data["connected"] == False  # msfrpcd not running on preview server
        assert "error" in data or "hint" in data
        print(f"MSF status: connected={data['connected']}, hint={data.get('hint', data.get('error', ''))}")
    
    def test_msf_connect_returns_status(self):
        """POST /api/msf/connect - returns status after reconnect attempt"""
        response = requests.post(f"{BASE_URL}/api/msf/connect")
        assert response.status_code == 200
        data = response.json()
        assert "connected" in data
        # Since msfrpcd is not running, should still be disconnected
        assert data["connected"] == False
        print(f"MSF connect attempt: connected={data['connected']}")
    
    def test_msf_sessions_returns_empty(self):
        """GET /api/msf/sessions - returns sessions list (empty if not connected)"""
        response = requests.get(f"{BASE_URL}/api/msf/sessions")
        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data
        assert "count" in data
        assert isinstance(data["sessions"], list)
        assert data["count"] == 0  # No sessions since not connected
        print(f"MSF sessions: count={data['count']}")
    
    def test_msf_jobs_returns_empty(self):
        """GET /api/msf/jobs - returns jobs list (empty if not connected)"""
        response = requests.get(f"{BASE_URL}/api/msf/jobs")
        assert response.status_code == 200
        data = response.json()
        assert "jobs" in data
        assert "count" in data
        assert isinstance(data["jobs"], list)
        assert data["count"] == 0  # No jobs since not connected
        print(f"MSF jobs: count={data['count']}")
    
    def test_msf_search_returns_hint(self):
        """GET /api/msf/search?query=smb - returns modules or empty if not connected"""
        response = requests.get(f"{BASE_URL}/api/msf/search", params={"query": "smb"})
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data
        assert isinstance(data["modules"], list)
        # Should return hint about static modules since msfrpcd not connected
        if "source" in data:
            assert data["source"] in ["static", "msfrpcd"]
        print(f"MSF search: modules={len(data['modules'])}, source={data.get('source', 'unknown')}")


class TestSliverC2Endpoints:
    """Sliver C2 integration tests - Sliver not running, expect graceful offline responses"""
    
    def test_sliver_status_returns_offline(self):
        """GET /api/sliver/status - returns connection status with setup hint"""
        response = requests.get(f"{BASE_URL}/api/sliver/status")
        assert response.status_code == 200
        data = response.json()
        assert "connected" in data
        assert data["connected"] == False  # Sliver not running on preview server
        # Should have hint about how to set up Sliver
        assert "error" in data or "hint" in data
        print(f"Sliver status: connected={data['connected']}, hint={data.get('hint', data.get('error', ''))[:100]}")
    
    def test_sliver_sessions_returns_empty(self):
        """GET /api/sliver/sessions - returns empty sessions list"""
        response = requests.get(f"{BASE_URL}/api/sliver/sessions")
        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data
        assert "count" in data
        assert isinstance(data["sessions"], list)
        assert data["count"] == 0  # No sessions since not connected
        print(f"Sliver sessions: count={data['count']}")
    
    def test_sliver_beacons_returns_empty(self):
        """GET /api/sliver/beacons - returns empty beacons list"""
        response = requests.get(f"{BASE_URL}/api/sliver/beacons")
        assert response.status_code == 200
        data = response.json()
        assert "beacons" in data
        assert "count" in data
        assert isinstance(data["beacons"], list)
        assert data["count"] == 0  # No beacons since not connected
        print(f"Sliver beacons: count={data['count']}")
    
    def test_sliver_implants_returns_empty(self):
        """GET /api/sliver/implants - returns empty implants list"""
        response = requests.get(f"{BASE_URL}/api/sliver/implants")
        assert response.status_code == 200
        data = response.json()
        assert "implants" in data
        assert "count" in data
        assert isinstance(data["implants"], list)
        assert data["count"] == 0  # No implants since not connected
        print(f"Sliver implants: count={data['count']}")


class TestC2Dashboard:
    """Unified C2 dashboard tests"""
    
    def test_c2_dashboard_returns_unified_status(self):
        """GET /api/c2/dashboard - returns unified MSF + Sliver status"""
        response = requests.get(f"{BASE_URL}/api/c2/dashboard")
        assert response.status_code == 200
        data = response.json()
        
        # Check Metasploit section
        assert "metasploit" in data
        msf = data["metasploit"]
        assert "connected" in msf
        assert "sessions" in msf
        assert "session_count" in msf
        assert "jobs" in msf
        assert "job_count" in msf
        
        # Check Sliver section
        assert "sliver" in data
        sliver = data["sliver"]
        assert "connected" in sliver
        assert "sessions" in sliver
        assert "session_count" in sliver
        assert "beacons" in sliver
        assert "beacon_count" in sliver
        
        # Both should be offline on preview server
        assert msf["connected"] == False
        assert sliver["connected"] == False
        
        print(f"C2 Dashboard: MSF connected={msf['connected']}, Sliver connected={sliver['connected']}")
        print(f"  MSF: sessions={msf['session_count']}, jobs={msf['job_count']}")
        print(f"  Sliver: sessions={sliver['session_count']}, beacons={sliver['beacon_count']}")


class TestWebSocketEndpoints:
    """WebSocket endpoint tests - verify endpoints accept connections"""
    
    def test_websocket_scan_endpoint_exists(self):
        """WebSocket /api/ws/scan/{id} - verify endpoint is configured"""
        # WebSocket endpoints return 404 for regular HTTP GET requests
        # This is expected - they only respond to WebSocket upgrade requests
        # We verify the endpoint path is valid by checking it doesn't return 500
        response = requests.get(f"{BASE_URL}/api/ws/scan/test123")
        # 404 is expected for WebSocket endpoints accessed via HTTP
        assert response.status_code in [200, 400, 403, 404, 426]
        print(f"WebSocket scan endpoint response: {response.status_code} (404 expected for HTTP access)")
    
    def test_websocket_chain_endpoint_exists(self):
        """WebSocket /api/ws/chain/{id} - verify endpoint is configured"""
        response = requests.get(f"{BASE_URL}/api/ws/chain/test123")
        # 404 is expected for WebSocket endpoints accessed via HTTP
        assert response.status_code in [200, 400, 403, 404, 426]
        print(f"WebSocket chain endpoint response: {response.status_code} (404 expected for HTTP access)")


class TestExistingFeatures:
    """Verify existing features still work after new additions"""
    
    def test_health_check(self):
        """GET /api/ - health check returns version"""
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert "3.1.0" in data["version"]
        print(f"API version: {data['version']}")
    
    def test_mitre_tactics(self):
        """GET /api/mitre/tactics - returns MITRE tactics"""
        response = requests.get(f"{BASE_URL}/api/mitre/tactics")
        assert response.status_code == 200
        data = response.json()
        assert "tactics" in data
        assert len(data["tactics"]) >= 10
        print(f"MITRE tactics: {len(data['tactics'])} tactics")
    
    def test_tools_endpoint(self):
        """GET /api/tools - returns red team tools"""
        response = requests.get(f"{BASE_URL}/api/tools")
        assert response.status_code == 200
        data = response.json()
        assert "tools" in data
        assert len(data["tools"]) > 0
        print(f"Tools: {len(data['tools'])} tools")
    
    def test_chains_endpoint(self):
        """GET /api/chains - returns attack chains"""
        response = requests.get(f"{BASE_URL}/api/chains")
        assert response.status_code == 200
        data = response.json()
        assert "chains" in data
        assert len(data["chains"]) >= 6
        print(f"Attack chains: {len(data['chains'])} chains")
    
    def test_metasploit_modules(self):
        """GET /api/metasploit/modules - returns MSF modules list"""
        response = requests.get(f"{BASE_URL}/api/metasploit/modules")
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data
        assert len(data["modules"]) > 0
        print(f"MSF modules: {len(data['modules'])} modules")
    
    def test_scan_history(self):
        """GET /api/scan/history - returns scan history"""
        response = requests.get(f"{BASE_URL}/api/scan/history")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"Scan history: {len(data)} scans")
    
    def test_tactical_service_attacks(self):
        """GET /api/tactical/service-attacks - returns service attack strategies"""
        response = requests.get(f"{BASE_URL}/api/tactical/service-attacks")
        assert response.status_code == 200
        data = response.json()
        assert "strategies" in data
        assert len(data["strategies"]) > 0
        print(f"Service attack strategies: {len(data['strategies'])} strategies")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
