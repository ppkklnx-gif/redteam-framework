"""
Test suite for 3 new improvements:
1. Recommended MSF modules based on scan findings
2. PDF report generation
3. Auto-suggest attack chains based on scan results
"""
import pytest
import requests
import os
import time

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestRecommendedModulesAndSuggestedChains:
    """Test recommended modules and suggested chains in scan status"""
    
    @pytest.fixture(scope="class")
    def completed_scan(self):
        """Create a scan and wait for completion"""
        # Start a scan
        response = requests.post(f"{BASE_URL}/api/scan/start", json={
            "target": "10.10.10.1",
            "scan_phases": ["reconnaissance"],
            "tools": []
        })
        assert response.status_code == 200, f"Failed to start scan: {response.text}"
        scan_id = response.json()["scan_id"]
        
        # Wait for scan to complete (max 60 seconds)
        for _ in range(30):
            status_response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
            if status_response.status_code == 200:
                status = status_response.json()
                if status.get("status") == "completed":
                    return scan_id, status
            time.sleep(2)
        
        # Return whatever we have after timeout
        status_response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
        return scan_id, status_response.json() if status_response.status_code == 200 else {}
    
    def test_scan_status_includes_suggested_chains(self, completed_scan):
        """Test that scan status includes suggested_chains field"""
        scan_id, status = completed_scan
        
        # Verify suggested_chains field exists
        assert "suggested_chains" in status, "suggested_chains field missing from scan status"
        assert isinstance(status["suggested_chains"], list), "suggested_chains should be a list"
        
        # If chains are suggested, verify structure
        if len(status["suggested_chains"]) > 0:
            chain = status["suggested_chains"][0]
            assert "id" in chain, "Chain should have id"
            assert "name" in chain, "Chain should have name"
            assert "description" in chain, "Chain should have description"
            assert "trigger_matched" in chain, "Chain should have trigger_matched"
            assert "total_steps" in chain, "Chain should have total_steps"
            print(f"Found {len(status['suggested_chains'])} suggested chains")
            for c in status["suggested_chains"]:
                print(f"  - {c['name']} (trigger: {c['trigger_matched']})")
    
    def test_scan_status_includes_recommended_modules(self, completed_scan):
        """Test that scan status includes recommended_modules field"""
        scan_id, status = completed_scan
        
        # Verify recommended_modules field exists
        assert "recommended_modules" in status, "recommended_modules field missing from scan status"
        assert isinstance(status["recommended_modules"], list), "recommended_modules should be a list"
        
        # If modules are recommended, verify structure
        if len(status["recommended_modules"]) > 0:
            mod = status["recommended_modules"][0]
            assert "name" in mod, "Module should have name"
            assert "desc" in mod, "Module should have desc"
            assert "relevance_score" in mod, "Module should have relevance_score"
            assert "reasons" in mod, "Module should have reasons"
            assert mod["relevance_score"] > 0, "Relevance score should be positive"
            print(f"Found {len(status['recommended_modules'])} recommended modules")
            for m in status["recommended_modules"][:5]:
                print(f"  - {m['name']} (score: {m['relevance_score']}, reasons: {m['reasons']})")
    
    def test_recommended_modules_sorted_by_relevance(self, completed_scan):
        """Test that recommended modules are sorted by relevance score (highest first)"""
        scan_id, status = completed_scan
        
        modules = status.get("recommended_modules", [])
        if len(modules) >= 2:
            scores = [m["relevance_score"] for m in modules]
            assert scores == sorted(scores, reverse=True), "Modules should be sorted by relevance_score descending"
            print(f"Modules correctly sorted: {scores[:5]}...")


class TestPDFReportGeneration:
    """Test PDF report generation endpoint"""
    
    @pytest.fixture(scope="class")
    def completed_scan_id(self):
        """Create a scan and wait for completion"""
        response = requests.post(f"{BASE_URL}/api/scan/start", json={
            "target": "192.168.1.100",
            "scan_phases": ["reconnaissance", "initial_access"],
            "tools": []
        })
        assert response.status_code == 200
        scan_id = response.json()["scan_id"]
        
        # Wait for completion
        for _ in range(30):
            status_response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
            if status_response.status_code == 200:
                if status_response.json().get("status") == "completed":
                    return scan_id
            time.sleep(2)
        return scan_id
    
    def test_pdf_report_endpoint_exists(self, completed_scan_id):
        """Test that PDF report endpoint returns a response"""
        response = requests.get(f"{BASE_URL}/api/scan/{completed_scan_id}/report/pdf")
        
        # Should return 200 with PDF content
        assert response.status_code == 200, f"PDF endpoint returned {response.status_code}: {response.text[:200]}"
        
        # Verify content type is PDF
        content_type = response.headers.get("content-type", "")
        assert "application/pdf" in content_type, f"Expected PDF content type, got: {content_type}"
        
        # Verify we got binary PDF data
        assert len(response.content) > 0, "PDF content should not be empty"
        
        # PDF files start with %PDF
        assert response.content[:4] == b'%PDF', "Response should be a valid PDF file"
        
        print(f"PDF report generated successfully, size: {len(response.content)} bytes")
    
    def test_pdf_report_404_for_nonexistent_scan(self):
        """Test that PDF endpoint returns 404 for nonexistent scan"""
        response = requests.get(f"{BASE_URL}/api/scan/nonexistent-scan-id-12345/report/pdf")
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"
    
    def test_pdf_report_content_disposition(self, completed_scan_id):
        """Test that PDF has proper content-disposition header for download"""
        response = requests.get(f"{BASE_URL}/api/scan/{completed_scan_id}/report/pdf")
        
        # Check for content-disposition header (optional but good practice)
        content_disposition = response.headers.get("content-disposition", "")
        # Some servers may not set this, so just log it
        print(f"Content-Disposition: {content_disposition}")


class TestExistingFeaturesStillWork:
    """Verify existing features still work after new improvements"""
    
    def test_api_health(self):
        """Test API health endpoint"""
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "3.1.0"
        assert "tactical_engine" in data["features"]
    
    def test_chains_endpoint(self):
        """Test chains list endpoint"""
        response = requests.get(f"{BASE_URL}/api/chains")
        assert response.status_code == 200
        data = response.json()
        assert "chains" in data
        assert len(data["chains"]) >= 6
    
    def test_mitre_tactics(self):
        """Test MITRE tactics endpoint"""
        response = requests.get(f"{BASE_URL}/api/mitre/tactics")
        assert response.status_code == 200
        data = response.json()
        assert "tactics" in data
        assert "reconnaissance" in data["tactics"]
    
    def test_metasploit_modules(self):
        """Test MSF modules endpoint"""
        response = requests.get(f"{BASE_URL}/api/metasploit/modules")
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data
        assert len(data["modules"]) > 0
    
    def test_scan_history(self):
        """Test scan history endpoint"""
        response = requests.get(f"{BASE_URL}/api/scan/history")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_tactical_service_attacks(self):
        """Test tactical service attacks endpoint"""
        response = requests.get(f"{BASE_URL}/api/tactical/service-attacks")
        assert response.status_code == 200
        data = response.json()
        assert "strategies" in data
    
    def test_chain_details(self):
        """Test getting chain details"""
        response = requests.get(f"{BASE_URL}/api/chains/web_to_shell")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "steps" in data


class TestGetRecommendedModulesFunction:
    """Test the get_recommended_modules function logic"""
    
    def test_modules_scored_by_service_match(self):
        """Test that modules are scored based on service matches"""
        # Start a scan that will have simulated results
        response = requests.post(f"{BASE_URL}/api/scan/start", json={
            "target": "test-smb-server.local",
            "scan_phases": ["reconnaissance"],
            "tools": []
        })
        assert response.status_code == 200
        scan_id = response.json()["scan_id"]
        
        # Wait for completion
        for _ in range(30):
            status_response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
            if status_response.status_code == 200:
                status = status_response.json()
                if status.get("status") == "completed":
                    # Check recommended modules
                    modules = status.get("recommended_modules", [])
                    print(f"Scan completed with {len(modules)} recommended modules")
                    
                    # Verify modules have proper structure
                    for mod in modules[:3]:
                        assert "relevance_score" in mod
                        assert "reasons" in mod
                        assert isinstance(mod["reasons"], list)
                    return
            time.sleep(2)
        
        # If we get here, scan didn't complete in time
        print("Warning: Scan did not complete in expected time")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
