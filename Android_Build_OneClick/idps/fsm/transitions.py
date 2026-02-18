"""
Finite State Machine Transition Rules
Formal transition definitions ensuring only valid state changes occur.
"""

from typing import Set, Optional, Dict
from enum import Enum
from dataclasses import dataclass
from collections import deque
from idps.fsm.states import SystemState


class TransitionResult(Enum):
    """Result of a transition attempt."""
    SUCCESS = "success"
    INVALID_TRANSITION = "invalid_transition"
    GUARD_FAILED = "guard_failed"
    ALREADY_IN_STATE = "already_in_state"


@dataclass
class Transition:
    """Represents a valid state transition."""
    from_state: SystemState
    to_state: SystemState
    event_type: str
    guard_condition: Optional[str] = None  # Name of guard function to check
    
    def __repr__(self) -> str:
        return f"{self.from_state.name} --[{self.event_type}]--> {self.to_state.name}"


class TransitionRules:
    """
    Formal transition rules defining valid state changes.
    This ensures the system never enters an undefined state.
    """
    
    # Define valid transitions: (from_state, to_state, event_type)
    VALID_TRANSITIONS: Set[tuple[SystemState, SystemState, str]] = {
        # Authentication flow
        (SystemState.UNAUTHENTICATED, SystemState.AUTHENTICATING, "auth_requested"),
        (SystemState.AUTHENTICATING, SystemState.AUTHORIZED_IDLE, "auth_success"),
        (SystemState.AUTHENTICATING, SystemState.UNAUTHENTICATED, "auth_failed"),
        (SystemState.AUTHENTICATING, SystemState.ERROR, "auth_error"),
        
        # Sync flow (requires authentication)
        (SystemState.AUTHORIZED_IDLE, SystemState.SYNCING, "sync_requested"),
        (SystemState.SYNCING, SystemState.AUTHORIZED_IDLE, "sync_complete"),
        (SystemState.SYNCING, SystemState.ERROR, "sync_error"),
        (SystemState.SYNCING, SystemState.AUTHORIZED_IDLE, "sync_timeout"),
        
        # Encryption flow
        (SystemState.AUTHORIZED_IDLE, SystemState.ENCRYPTING_DATA, "encrypt_requested"),
        (SystemState.ENCRYPTING_DATA, SystemState.AUTHORIZED_IDLE, "encrypt_complete"),
        (SystemState.ENCRYPTING_DATA, SystemState.ERROR, "encrypt_error"),
        
        # Error recovery
        (SystemState.ERROR, SystemState.UNAUTHENTICATED, "error_recovered"),
        (SystemState.ERROR, SystemState.AUTHORIZED_IDLE, "error_recovered"),
        (SystemState.ERROR, SystemState.SHUTDOWN, "shutdown_requested"),
        
        # Logout
        (SystemState.AUTHORIZED_IDLE, SystemState.UNAUTHENTICATED, "logout"),
        (SystemState.SYNCING, SystemState.UNAUTHENTICATED, "logout"),
        (SystemState.ENCRYPTING_DATA, SystemState.UNAUTHENTICATED, "logout"),
        
        # Shutdown (can happen from most states)
        (SystemState.UNAUTHENTICATED, SystemState.SHUTDOWN, "shutdown_requested"),
        (SystemState.AUTHORIZED_IDLE, SystemState.SHUTDOWN, "shutdown_requested"),
        (SystemState.ERROR, SystemState.SHUTDOWN, "shutdown_requested"),
    }
    
    # Guard conditions: (from_state, to_state, event_type) -> guard_function_name
    GUARD_CONDITIONS: Dict[tuple[SystemState, SystemState, str], str] = {
        (SystemState.AUTHORIZED_IDLE, SystemState.SYNCING, "sync_requested"): "check_network_available",
        (SystemState.AUTHORIZED_IDLE, SystemState.ENCRYPTING_DATA, "encrypt_requested"): "check_has_data_to_encrypt",
    }
    
    @classmethod
    def is_valid_transition(
        cls,
        from_state: SystemState,
        to_state: SystemState,
        event_type: str
    ) -> bool:
        """
        Check if a transition is valid according to the formal rules.
        
        Args:
            from_state: Current state
            to_state: Target state
            event_type: Type of event triggering the transition
            
        Returns:
            True if transition is valid, False otherwise
        """
        return (from_state, to_state, event_type) in cls.VALID_TRANSITIONS
    
    @classmethod
    def get_guard_condition(
        cls,
        from_state: SystemState,
        to_state: SystemState,
        event_type: str
    ) -> Optional[str]:
        """
        Get the guard condition function name for a transition.
        
        Returns:
            Guard function name or None if no guard is required
        """
        return cls.GUARD_CONDITIONS.get((from_state, to_state, event_type))
    
    @classmethod
    def get_valid_targets(
        cls,
        from_state: SystemState,
        event_type: Optional[str] = None
    ) -> Set[SystemState]:
        """
        Get all valid target states from a given state.
        
        Args:
            from_state: Current state
            event_type: Optional event type to filter transitions
            
        Returns:
            Set of valid target states
        """
        targets = set()
        for f_state, t_state, e_type in cls.VALID_TRANSITIONS:
            if f_state == from_state:
                if event_type is None or e_type == event_type:
                    targets.add(t_state)
        return targets
    
    @classmethod
    def get_transition_path(
        cls,
        from_state: SystemState,
        to_state: SystemState
    ) -> Optional[list[Transition]]:
        """
        Find a valid transition path between two states.
        Uses breadth-first search to find shortest path.
        
        Returns:
            List of transitions or None if no path exists
        """
        if from_state == to_state:
            return []
        
        # Build transition graph
        graph: Dict[SystemState, Set[tuple[SystemState, str]]] = {}
        for f_state, t_state, e_type in cls.VALID_TRANSITIONS:
            if f_state not in graph:
                graph[f_state] = set()
            graph[f_state].add((t_state, e_type))
        
        # BFS to find path
        queue = deque([(from_state, [])])
        visited = {from_state}
        
        while queue:
            current_state, path = queue.popleft()
            
            if current_state == to_state:
                return path
            
            if current_state not in graph:
                continue
            
            for next_state, event_type in graph[current_state]:
                if next_state not in visited:
                    visited.add(next_state)
                    new_path = path + [Transition(
                        from_state=current_state,
                        to_state=next_state,
                        event_type=event_type
                    )]
                    queue.append((next_state, new_path))
        
        return None  # No path found

