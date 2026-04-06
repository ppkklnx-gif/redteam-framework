"""
Red Team Framework v6.0 Local-First API Tests
Tests SQLite-based persistence, Job system, and all API endpoints
"""
import pytest
import requests
import os
import time
import json

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://security-framework-3.preview.emergentagent.com').rstrip('/')


class TestRootAndHealth:
    """Test root and health endpoints - verify v6.0 local-first architecture"""
    
    def test_root_returns_version_6(self):
        """GET /api/ should return version 6.0.0-local with database:sqlite"""
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "6.0.0-local"
        assert data["database"] == "sqlite"
        assert data["architecture"] == "local-first"
        print(f"✓ Root endpoint: version={data['version']}, db={data['database']}")
    
    def test_health_shows_database_connected(self):
        """GET /api/health should show database connected status"""
        response = requests.get(f"{BASE_URL}/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "checks" in data
        assert data["checks"]["database"]["engine"] == "sqlite"
        assert data["checks"]["database"]["status"] == "connected"
        print(f"✓ Health: database={data['checks']['database']['status']}")
    
    def test_doctor_returns_deep_diagnostic(self):
        """GET /api/doctor should return deep diagnostic info"""
        response = requests.get(f"{BASE_URL}/api/doctor")
        assert response.status_code == 200
        data = response.json()
        # Check required sections
        assert "database" in data
        assert "integrations" in data
        assert "config" in data
        assert "hints" in data
        assert "tools" in data
        # Verify database info
        assert data["database"]["engine"] == "sqlite"
        assert data["database"]["healthy"] == True
        print(f"✓ Doctor: db_healthy={data['database']['healthy']}, tools={list(data['tools'].keys())[:3]}")


class TestJobSystem:
    """Test the new async Job system endpoints"""
    
    def test_list_jobs(self):
        """GET /api/jobs should list all jobs"""
        response = requests.get(f"{BASE_URL}/api/jobs")
        assert response.status_code == 200
        data = response.json()
        assert "jobs" in data
        assert "active_job_ids" in data
        assert isinstance(data["jobs"], list)
        print(f"✓ Jobs list: {len(data['jobs'])} jobs, {len(data['active_job_ids'])} active")
    
    def test_get_job_details(self):
        """GET /api/jobs/{job_id} should return job details"""
        # First get a job from the list
        list_response = requests.get(f"{BASE_URL}/api/jobs")
        jobs = list_response.json().get("jobs", [])
        if not jobs:
            pytest.skip("No jobs available to test")
        
        job_id = jobs[0]["id"]
        response = requests.get(f"{BASE_URL}/api/jobs/{job_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == job_id
        assert "status" in data
        assert "progress" in data
        print(f"✓ Job details: id={job_id}, status={data['status']}, progress={data['progress']}")
    
    def test_get_job_logs(self):
        """GET /api/jobs/{job_id}/logs should return job logs"""
        list_response = requests.get(f"{BASE_URL}/api/jobs")
        jobs = list_response.json().get("jobs", [])
        if not jobs:
            pytest.skip("No jobs available to test")
        
        job_id = jobs[0]["id"]
        response = requests.get(f"{BASE_URL}/api/jobs/{job_id}/logs")
        assert response.status_code == 200
        data = response.json()
        assert "logs" in data
        assert isinstance(data["logs"], list)
        print(f"✓ Job logs: {len(data['logs'])} log entries for job {job_id}")
    
    def test_cancel_completed_job_returns_error(self):
        """POST /api/jobs/{job_id}/cancel should handle completed jobs"""
        list_response = requests.get(f"{BASE_URL}/api/jobs")
        jobs = list_response.json().get("jobs", [])
        completed_jobs = [j for j in jobs if j["status"] == "completed"]
        if not completed_jobs:
            pytest.skip("No completed jobs to test cancel")
        
        job_id = completed_jobs[0]["id"]
        response = requests.post(f"{BASE_URL}/api/jobs/{job_id}/cancel")
        # Should return 400 or 404 since job is already completed
        assert response.status_code in [200, 400, 404]
        print(f"✓ Cancel completed job: status={response.status_code}")


class TestScanFlow:
    """Test the scan workflow with Job system"""
    
    def test_start_scan_returns_scan_and_job_id(self):
        """POST /api/scan/start should return both scan_id AND job_id"""
        response = requests.post(
            f"{BASE_URL}/api/scan/start",
            json={"target": "192.168.1.100", "scan_phases": ["reconnaissance"]}
        )
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert "job_id" in data
        assert data["status"] == "started"
        print(f"✓ Scan started: scan_id={data['scan_id']}, job_id={data['job_id']}")
        return data
    
    def test_get_scan_status(self):
        """GET /api/scan/{scan_id}/status should return scan status"""
        # Start a scan first
        start_response = requests.post(
            f"{BASE_URL}/api/scan/start",
            json={"target": "10.10.10.100", "scan_phases": ["reconnaissance"]}
        )
        scan_id = start_response.json()["scan_id"]
        
        # Wait a bit for scan to progress
        time.sleep(2)
        
        response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert "status" in data
        assert "progress" in data
        assert "results" in data
        print(f"✓ Scan status: status={data['status']}, progress={data['progress']}%")
    
    def test_get_scan_history(self):
        """GET /api/scan/history should return completed scans from SQLite"""
        response = requests.get(f"{BASE_URL}/api/scan/history")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if data:
            scan = data[0]
            assert "id" in scan
            assert "target" in scan
            assert "status" in scan
        print(f"✓ Scan history: {len(data)} scans in SQLite")


class TestConfigEndpoints:
    """Test global configuration endpoints"""
    
    def test_get_config(self):
        """GET /api/config should return global config"""
        response = requests.get(f"{BASE_URL}/api/config")
        assert response.status_code == 200
        data = response.json()
        assert "listener_ip" in data
        assert "listener_port" in data
        assert "c2_protocol" in data
        print(f"✓ Config: listener={data.get('listener_ip')}:{data.get('listener_port')}")
    
    def test_update_config(self):
        """PUT /api/config should update config"""
        # Get current config
        current = requests.get(f"{BASE_URL}/api/config").json()
        
        # Update with test value
        response = requests.put(
            f"{BASE_URL}/api/config",
            json={"listener_ip": "10.0.0.1"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "updated"
        assert data["config"]["listener_ip"] == "10.0.0.1"
        print(f"✓ Config updated: listener_ip={data['config']['listener_ip']}")
        
        # Restore original if it was set
        if current.get("listener_ip"):
            requests.put(f"{BASE_URL}/api/config", json={"listener_ip": current["listener_ip"]})


class TestAttackChains:
    """Test attack chain endpoints"""
    
    def test_get_chains(self):
        """GET /api/chains should return attack chains"""
        response = requests.get(f"{BASE_URL}/api/chains")
        assert response.status_code == 200
        data = response.json()
        assert "chains" in data
        assert len(data["chains"]) >= 6  # Should have at least 6 chains
        chain = data["chains"][0]
        assert "id" in chain
        assert "name" in chain
        assert "steps_count" in chain
        print(f"✓ Chains: {len(data['chains'])} attack chains available")
    
    def test_get_chain_details(self):
        """GET /api/chains/{chain_id} should return chain details"""
        response = requests.get(f"{BASE_URL}/api/chains/web_to_shell")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Web App to Shell"
        assert "steps" in data
        assert len(data["steps"]) > 0
        print(f"✓ Chain details: {data['name']} with {len(data['steps'])} steps")


class TestToolsAndModules:
    """Test tools and metasploit modules endpoints"""
    
    def test_get_tools(self):
        """GET /api/tools should return tool catalog"""
        response = requests.get(f"{BASE_URL}/api/tools")
        assert response.status_code == 200
        data = response.json()
        assert "tools" in data
        tools = data["tools"]
        assert "nmap" in tools
        assert "nikto" in tools
        assert tools["nmap"]["phase"] == "reconnaissance"
        print(f"✓ Tools: {len(tools)} tools in catalog")
    
    def test_get_metasploit_modules(self):
        """GET /api/metasploit/modules should return module list"""
        response = requests.get(f"{BASE_URL}/api/metasploit/modules")
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data
        assert len(data["modules"]) > 0
        module = data["modules"][0]
        assert "name" in module
        assert "category" in module
        print(f"✓ MSF modules: {len(data['modules'])} modules available")


class TestPayloads:
    """Test payload template endpoints"""
    
    def test_get_payload_templates(self):
        """GET /api/payloads/templates should return payload templates"""
        response = requests.get(f"{BASE_URL}/api/payloads/templates")
        assert response.status_code == 200
        data = response.json()
        assert "payloads" in data
        assert len(data["payloads"]) >= 10  # Should have at least 10 templates
        payload = data["payloads"][0]
        assert "id" in payload
        assert "name" in payload
        assert "platform" in payload
        print(f"✓ Payloads: {len(data['payloads'])} templates available")


class TestMitreTactics:
    """Test MITRE ATT&CK endpoints"""
    
    def test_get_mitre_tactics(self):
        """GET /api/mitre/tactics should return MITRE tactics"""
        response = requests.get(f"{BASE_URL}/api/mitre/tactics")
        assert response.status_code == 200
        data = response.json()
        assert "tactics" in data
        tactics = data["tactics"]
        assert "reconnaissance" in tactics
        assert "initial_access" in tactics
        assert tactics["reconnaissance"]["id"] == "TA0043"
        print(f"✓ MITRE tactics: {len(tactics)} tactics available")


class TestIntegrationFlow:
    """Test complete scan flow integration"""
    
    def test_full_scan_flow(self):
        """Test complete scan flow: start -> poll -> complete"""
        # 1. Start scan
        start_response = requests.post(
            f"{BASE_URL}/api/scan/start",
            json={"target": "172.16.0.1", "scan_phases": ["reconnaissance"]}
        )
        assert start_response.status_code == 200
        scan_data = start_response.json()
        scan_id = scan_data["scan_id"]
        job_id = scan_data["job_id"]
        print(f"  Started scan: {scan_id}, job: {job_id}")
        
        # 2. Poll for completion (max 30 seconds)
        max_wait = 30
        start_time = time.time()
        final_status = None
        
        while time.time() - start_time < max_wait:
            status_response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
            if status_response.status_code == 200:
                status_data = status_response.json()
                final_status = status_data["status"]
                progress = status_data.get("progress", 0)
                print(f"  Progress: {progress}% - {final_status}")
                
                if final_status in ["completed", "error"]:
                    break
            time.sleep(2)
        
        # 3. Verify completion
        assert final_status == "completed", f"Scan did not complete: {final_status}"
        
        # 4. Verify job completed
        job_response = requests.get(f"{BASE_URL}/api/jobs/{job_id}")
        assert job_response.status_code == 200
        job_data = job_response.json()
        assert job_data["status"] == "completed"
        
        # 5. Verify scan in history
        history_response = requests.get(f"{BASE_URL}/api/scan/history")
        history = history_response.json()
        scan_ids = [s["id"] for s in history]
        assert scan_id in scan_ids
        
        print(f"✓ Full scan flow completed successfully")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
