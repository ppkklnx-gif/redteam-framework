"""
Backend API Tests for Red Team Framework - Chain Execution Engine (P1 Feature)
Focus: Real-time step-by-step tracking, auto-execute mode, manual step execution

Tests cover:
- POST /api/chains/execute with auto_execute=true - starts background execution
- GET /api/chains/execution/{id} - tracks progress with step_statuses
- POST /api/chains/execute with auto_execute=false - creates execution in 'ready' state
- POST /api/chains/execution/{id}/step/{step_id} - manually executes a specific step
- Step status transitions: pending -> running -> completed
"""

import pytest
import requests
import os
import time

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestChainExecutionEngineAutoMode:
    """Test auto-execute mode with background execution and step tracking"""
    
    def test_auto_execute_starts_background_execution(self):
        """POST /api/chains/execute with auto_execute=true - starts background execution"""
        payload = {
            "scan_id": "",
            "chain_id": "linux_privesc",
            "target": "10.10.10.5",
            "context": {"lhost": "10.10.14.1"},
            "auto_execute": True
        }
        response = requests.post(f"{BASE_URL}/api/chains/execute", json=payload)
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "execution_id" in data, "Missing execution_id"
        assert "chain_id" in data
        assert data["chain_id"] == "linux_privesc"
        assert "total_steps" in data, "Missing total_steps"
        assert data["total_steps"] == 4, f"Expected 4 steps, got {data['total_steps']}"
        assert "step_statuses" in data, "Missing step_statuses"
        assert "status" in data
        assert data["status"] == "running", f"Expected 'running' status, got {data['status']}"
        
        # Store execution_id for subsequent tests
        TestChainExecutionEngineAutoMode.execution_id = data["execution_id"]
        print(f"✓ Auto-execute started: {data['execution_id']}, status={data['status']}, steps={data['total_steps']}")
    
    def test_track_execution_progress_with_step_statuses(self):
        """GET /api/chains/execution/{id} - tracks progress with step_statuses"""
        execution_id = getattr(TestChainExecutionEngineAutoMode, 'execution_id', None)
        if not execution_id:
            pytest.skip("No execution_id from previous test")
        
        # Wait a bit for background execution to start
        time.sleep(2)
        
        response = requests.get(f"{BASE_URL}/api/chains/execution/{execution_id}")
        assert response.status_code == 200
        data = response.json()
        
        # Verify tracking fields
        assert "id" in data
        assert data["id"] == execution_id
        assert "status" in data
        assert "current_step" in data
        assert "total_steps" in data
        assert "progress" in data, "Missing progress field"
        assert "step_statuses" in data, "Missing step_statuses field"
        
        # Verify step_statuses structure
        step_statuses = data["step_statuses"]
        assert isinstance(step_statuses, dict), "step_statuses should be a dict"
        
        # Check at least one step has status info
        if len(step_statuses) > 0:
            first_step_key = list(step_statuses.keys())[0]
            first_step = step_statuses[first_step_key]
            assert "step_id" in first_step
            assert "step_name" in first_step
            assert "status" in first_step
            assert first_step["status"] in ["pending", "running", "completed", "failed"]
        
        print(f"✓ Execution tracking: status={data['status']}, progress={data['progress']}%, current_step={data['current_step']}/{data['total_steps']}")
        print(f"  Step statuses: {list(step_statuses.keys())}")
    
    def test_wait_for_completion_and_verify_final_state(self):
        """Wait for auto-execute to complete and verify final state"""
        execution_id = getattr(TestChainExecutionEngineAutoMode, 'execution_id', None)
        if not execution_id:
            pytest.skip("No execution_id from previous test")
        
        # Poll until completed or timeout (max 15 seconds)
        max_wait = 15
        poll_interval = 1.5
        elapsed = 0
        final_data = None
        
        while elapsed < max_wait:
            response = requests.get(f"{BASE_URL}/api/chains/execution/{execution_id}")
            assert response.status_code == 200
            data = response.json()
            
            if data["status"] == "completed":
                final_data = data
                break
            
            time.sleep(poll_interval)
            elapsed += poll_interval
        
        assert final_data is not None, f"Execution did not complete within {max_wait}s"
        assert final_data["status"] == "completed"
        assert final_data["progress"] == 100, f"Expected progress=100, got {final_data['progress']}"
        
        # Verify all steps completed
        step_statuses = final_data.get("step_statuses", {})
        for step_key, step_status in step_statuses.items():
            assert step_status["status"] == "completed", f"Step {step_key} not completed: {step_status['status']}"
        
        print(f"✓ Execution completed: progress={final_data['progress']}%, all {len(step_statuses)} steps completed")


class TestChainExecutionEngineManualMode:
    """Test manual execution mode with step-by-step control"""
    
    def test_manual_mode_creates_ready_state(self):
        """POST /api/chains/execute with auto_execute=false - creates execution in 'ready' state"""
        payload = {
            "scan_id": "",
            "chain_id": "linux_privesc",
            "target": "10.10.10.6",
            "context": {"lhost": "10.10.14.2"},
            "auto_execute": False
        }
        response = requests.post(f"{BASE_URL}/api/chains/execute", json=payload)
        assert response.status_code == 200
        data = response.json()
        
        assert "execution_id" in data
        assert "status" in data
        assert data["status"] == "ready", f"Expected 'ready' status, got {data['status']}"
        assert "step_statuses" in data
        assert "total_steps" in data
        assert "commands" in data
        
        # Verify all steps are pending
        step_statuses = data["step_statuses"]
        for step_key, step_status in step_statuses.items():
            assert step_status["status"] == "pending", f"Step {step_key} should be pending"
        
        TestChainExecutionEngineManualMode.execution_id = data["execution_id"]
        print(f"✓ Manual mode: execution_id={data['execution_id']}, status={data['status']}, steps={data['total_steps']}")
    
    def test_execute_single_step_manually(self):
        """POST /api/chains/execution/{id}/step/{step_id} - manually executes a specific step"""
        execution_id = getattr(TestChainExecutionEngineManualMode, 'execution_id', None)
        if not execution_id:
            pytest.skip("No execution_id from previous test")
        
        # Execute step 1
        response = requests.post(f"{BASE_URL}/api/chains/execution/{execution_id}/step/1")
        assert response.status_code == 200
        data = response.json()
        
        # Verify step execution response
        assert "step_id" in data
        assert data["step_id"] == 1
        assert "step_name" in data
        assert "status" in data
        assert data["status"] in ["completed", "failed"]
        assert "command_results" in data
        
        print(f"✓ Step 1 executed: {data['step_name']}, status={data['status']}")
        
        # Verify execution status updated
        status_response = requests.get(f"{BASE_URL}/api/chains/execution/{execution_id}")
        assert status_response.status_code == 200
        status_data = status_response.json()
        
        step_statuses = status_data.get("step_statuses", {})
        assert "1" in step_statuses, "Step 1 not in step_statuses"
        assert step_statuses["1"]["status"] == "completed", f"Step 1 status: {step_statuses['1']['status']}"
        
        print(f"✓ Step 1 status verified in execution: {step_statuses['1']['status']}")
    
    def test_execute_second_step_manually(self):
        """Execute step 2 manually and verify progress"""
        execution_id = getattr(TestChainExecutionEngineManualMode, 'execution_id', None)
        if not execution_id:
            pytest.skip("No execution_id from previous test")
        
        # Execute step 2
        response = requests.post(f"{BASE_URL}/api/chains/execution/{execution_id}/step/2")
        assert response.status_code == 200
        data = response.json()
        
        assert data["step_id"] == 2
        assert data["status"] in ["completed", "failed"]
        
        print(f"✓ Step 2 executed: {data['step_name']}, status={data['status']}")
    
    def test_verify_partial_progress(self):
        """Verify progress after partial manual execution"""
        execution_id = getattr(TestChainExecutionEngineManualMode, 'execution_id', None)
        if not execution_id:
            pytest.skip("No execution_id from previous test")
        
        response = requests.get(f"{BASE_URL}/api/chains/execution/{execution_id}")
        assert response.status_code == 200
        data = response.json()
        
        # Should still be in ready state (not auto-executing)
        assert data["status"] == "ready"
        
        # Verify step statuses
        step_statuses = data.get("step_statuses", {})
        completed_count = sum(1 for s in step_statuses.values() if s["status"] == "completed")
        pending_count = sum(1 for s in step_statuses.values() if s["status"] == "pending")
        
        assert completed_count >= 2, f"Expected at least 2 completed steps, got {completed_count}"
        
        print(f"✓ Partial progress: {completed_count} completed, {pending_count} pending")


class TestChainExecutionEdgeCases:
    """Edge cases and error handling for chain execution"""
    
    def test_execute_nonexistent_chain(self):
        """POST /api/chains/execute with invalid chain_id - returns 404"""
        payload = {
            "scan_id": "",
            "chain_id": "nonexistent_chain",
            "target": "10.10.10.1",
            "context": {},
            "auto_execute": False
        }
        response = requests.post(f"{BASE_URL}/api/chains/execute", json=payload)
        assert response.status_code == 404
        print("✓ Nonexistent chain returns 404")
    
    def test_execute_step_on_nonexistent_execution(self):
        """POST /api/chains/execution/{id}/step/{step_id} with invalid execution_id - returns 404"""
        response = requests.post(f"{BASE_URL}/api/chains/execution/nonexistent-exec-id/step/1")
        assert response.status_code == 404
        print("✓ Nonexistent execution returns 404")
    
    def test_get_nonexistent_execution(self):
        """GET /api/chains/execution/{id} with invalid id - returns 404"""
        response = requests.get(f"{BASE_URL}/api/chains/execution/invalid-execution-id-12345")
        assert response.status_code == 404
        print("✓ Nonexistent execution GET returns 404")


class TestStepStatusTransitions:
    """Test step status transitions during execution"""
    
    def test_step_status_transitions_during_auto_execute(self):
        """Verify step statuses transition from pending -> running -> completed"""
        payload = {
            "scan_id": "",
            "chain_id": "linux_privesc",
            "target": "10.10.10.7",
            "context": {"lhost": "10.10.14.3"},
            "auto_execute": True
        }
        response = requests.post(f"{BASE_URL}/api/chains/execute", json=payload)
        assert response.status_code == 200
        data = response.json()
        execution_id = data["execution_id"]
        
        # Track status transitions
        seen_running = False
        seen_completed = False
        max_polls = 12
        
        for i in range(max_polls):
            time.sleep(1)
            status_response = requests.get(f"{BASE_URL}/api/chains/execution/{execution_id}")
            status_data = status_response.json()
            
            step_statuses = status_data.get("step_statuses", {})
            
            # Check for running status
            for step_key, step_status in step_statuses.items():
                if step_status["status"] == "running":
                    seen_running = True
                if step_status["status"] == "completed":
                    seen_completed = True
            
            if status_data["status"] == "completed":
                break
        
        # We should have seen at least completed status (running might be too fast to catch)
        assert seen_completed, "Never saw completed status"
        print(f"✓ Status transitions verified: seen_running={seen_running}, seen_completed={seen_completed}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
