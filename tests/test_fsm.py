"""
Unit tests for the FSM module
Tests formal correctness and transition validation.
"""

import pytest
import asyncio
from idps.fsm import (
    FSMController,
    SystemState,
    Event,
    EventType,
    TransitionRules,
    TransitionResult,
    StateTransitionError,
    StateRegistry
)


class TestStateDefinitions:
    """Test state definitions and metadata."""
    
    def test_all_states_have_metadata(self):
        """Ensure all states have associated metadata."""
        for state in SystemState:
            metadata = StateRegistry.get_metadata(state)
            assert metadata is not None, f"State {state.name} missing metadata"
            assert metadata.name == state.name
    
    def test_initial_state_is_unauthenticated(self):
        """Test that initial state is UNAUTHENTICATED."""
        fsm = FSMController()
        assert fsm.current_state == SystemState.UNAUTHENTICATED


class TestTransitionRules:
    """Test transition rule validation."""
    
    def test_valid_transitions(self):
        """Test that valid transitions are accepted."""
        assert TransitionRules.is_valid_transition(
            SystemState.UNAUTHENTICATED,
            SystemState.AUTHENTICATING,
            "auth_requested"
        )
        
        assert TransitionRules.is_valid_transition(
            SystemState.AUTHENTICATING,
            SystemState.AUTHORIZED_IDLE,
            "auth_success"
        )
    
    def test_invalid_transitions(self):
        """Test that invalid transitions are rejected."""
        # Cannot go from UNAUTHENTICATED to SYNCING
        assert not TransitionRules.is_valid_transition(
            SystemState.UNAUTHENTICATED,
            SystemState.SYNCING,
            "sync_requested"
        )
        
        # Cannot go from AUTHENTICATING to ENCRYPTING_DATA
        assert not TransitionRules.is_valid_transition(
            SystemState.AUTHENTICATING,
            SystemState.ENCRYPTING_DATA,
            "encrypt_requested"
        )
    
    def test_get_valid_targets(self):
        """Test getting valid target states."""
        targets = TransitionRules.get_valid_targets(
            SystemState.UNAUTHENTICATED,
            "auth_requested"
        )
        assert SystemState.AUTHENTICATING in targets
    
    def test_transition_path_finding(self):
        """Test finding valid transition paths."""
        # Path from UNAUTHENTICATED to AUTHORIZED_IDLE exists
        path = TransitionRules.get_transition_path(
            SystemState.UNAUTHENTICATED,
            SystemState.AUTHORIZED_IDLE
        )
        assert path is not None
        assert len(path) > 0


class TestFSMController:
    """Test FSM controller functionality."""
    
    @pytest.mark.asyncio
    async def test_initial_state(self):
        """Test FSM starts in correct initial state."""
        fsm = FSMController()
        assert fsm.current_state == SystemState.UNAUTHENTICATED
    
    @pytest.mark.asyncio
    async def test_valid_transition(self):
        """Test a valid state transition."""
        fsm = FSMController()
        result = await fsm.transition(
            SystemState.AUTHENTICATING,
            "auth_requested"
        )
        assert result == TransitionResult.SUCCESS
        assert fsm.current_state == SystemState.AUTHENTICATING
    
    @pytest.mark.asyncio
    async def test_invalid_transition(self):
        """Test that invalid transitions are rejected."""
        fsm = FSMController()
        result = await fsm.transition(
            SystemState.SYNCING,
            "sync_requested"
        )
        assert result == TransitionResult.INVALID_TRANSITION
        assert fsm.current_state == SystemState.UNAUTHENTICATED
    
    @pytest.mark.asyncio
    async def test_event_processing(self):
        """Test event processing triggers transitions."""
        fsm = FSMController()
        await fsm.start()
        
        auth_event = Event(
            event_type=EventType.AUTH_REQUESTED,
            source="test"
        )
        result = await fsm.process_event(auth_event)
        assert result == TransitionResult.SUCCESS
        assert fsm.current_state == SystemState.AUTHENTICATING
        
        await fsm.stop()
    
    @pytest.mark.asyncio
    async def test_state_history(self):
        """Test state transition history tracking."""
        fsm = FSMController()
        
        await fsm.transition(SystemState.AUTHENTICATING, "auth_requested")
        await fsm.transition(SystemState.AUTHORIZED_IDLE, "auth_success")
        
        history = fsm.get_state_history()
        assert len(history) == 2
        assert history[0][0] == SystemState.AUTHENTICATING
        assert history[1][0] == SystemState.AUTHORIZED_IDLE
    
    @pytest.mark.asyncio
    async def test_guard_condition(self):
        """Test guard condition enforcement."""
        fsm = FSMController()
        
        # Transition to AUTHORIZED_IDLE first
        await fsm.transition(SystemState.AUTHENTICATING, "auth_requested")
        await fsm.transition(SystemState.AUTHORIZED_IDLE, "auth_success")
        
        # Try to sync without network (should fail guard)
        fsm.update_context({"network_available": False})
        result = await fsm.transition(
            SystemState.SYNCING,
            "sync_requested"
        )
        assert result == TransitionResult.GUARD_FAILED
        
        # Enable network and try again (should succeed)
        fsm.update_context({"network_available": True})
        result = await fsm.transition(
            SystemState.SYNCING,
            "sync_requested"
        )
        assert result == TransitionResult.SUCCESS
    
    @pytest.mark.asyncio
    async def test_state_handler(self):
        """Test state handler invocation."""
        fsm = FSMController()
        
        handler_called = False
        
        async def handler(context):
            nonlocal handler_called
            handler_called = True
        
        fsm.register_state_handler(SystemState.AUTHENTICATING, handler)
        
        await fsm.transition(SystemState.AUTHENTICATING, "auth_requested")
        assert handler_called
    
    @pytest.mark.asyncio
    async def test_transition_callback(self):
        """Test transition callback invocation."""
        fsm = FSMController()
        
        callback_called = False
        
        def callback(from_state, to_state, event_type):
            nonlocal callback_called
            callback_called = True
            assert from_state == SystemState.UNAUTHENTICATED
            assert to_state == SystemState.AUTHENTICATING
        
        fsm.register_transition_callback(callback)
        
        await fsm.transition(SystemState.AUTHENTICATING, "auth_requested")
        assert callback_called
    
    @pytest.mark.asyncio
    async def test_concurrent_events(self):
        """Test handling concurrent events."""
        fsm = FSMController()
        await fsm.start()
        
        # Send multiple events
        events = [
            Event(EventType.AUTH_REQUESTED, source="test"),
            Event(EventType.AUTH_SUCCESS, source="test"),
        ]
        
        for event in events:
            await fsm.send_event(event)
        
        # Wait for processing
        await asyncio.sleep(0.5)
        
        await fsm.stop()
        # Should end up in AUTHORIZED_IDLE after processing both events
        assert fsm.current_state == SystemState.AUTHORIZED_IDLE


class TestEventSystem:
    """Test event handling system."""
    
    def test_event_creation(self):
        """Test event creation and serialization."""
        event = Event(
            event_type=EventType.AUTH_REQUESTED,
            source="test",
            payload={"key": "value"}
        )
        
        assert event.event_type == EventType.AUTH_REQUESTED
        assert event.source == "test"
        assert event.payload["key"] == "value"
        
        # Test serialization
        event_dict = event.to_dict()
        assert event_dict["event_type"] == "auth_requested"
        
        # Test deserialization
        restored_event = Event.from_dict(event_dict)
        assert restored_event.event_type == EventType.AUTH_REQUESTED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

