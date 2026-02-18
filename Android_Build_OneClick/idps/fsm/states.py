"""
Finite State Machine State Definitions for IDPS
Formal state definitions ensuring the application never enters an undefined state.
"""

from enum import Enum, auto
from typing import Set, Optional
from dataclasses import dataclass


class SystemState(Enum):
    """
    Explicit state definitions for the IDPS system.
    Each state represents a well-defined system condition.
    """
    UNAUTHENTICATED = auto()      # Initial state, no user authentication
    AUTHENTICATING = auto()        # Authentication in progress
    SYNCING = auto()               # Synchronizing with cloud/server
    AUTHORIZED_IDLE = auto()       # Authenticated and ready, no active operations
    ENCRYPTING_DATA = auto()       # Encrypting sensitive data
    ERROR = auto()                 # Error state requiring recovery
    SHUTDOWN = auto()              # Graceful shutdown state


@dataclass(frozen=True)
class StateMetadata:
    """Metadata associated with each state for validation and logging."""
    name: str
    description: str
    is_terminal: bool = False
    allows_user_input: bool = True
    requires_network: bool = False
    requires_authentication: bool = False


class StateRegistry:
    """Registry of state metadata for validation and introspection."""
    
    METADATA: dict[SystemState, StateMetadata] = {
        SystemState.UNAUTHENTICATED: StateMetadata(
            name="UNAUTHENTICATED",
            description="Initial state before user authentication",
            allows_user_input=True,
            requires_network=False,
            requires_authentication=False
        ),
        SystemState.AUTHENTICATING: StateMetadata(
            name="AUTHENTICATING",
            description="Authentication process in progress",
            allows_user_input=False,
            requires_network=True,
            requires_authentication=False
        ),
        SystemState.SYNCING: StateMetadata(
            name="SYNCING",
            description="Synchronizing data with remote server",
            allows_user_input=False,
            requires_network=True,
            requires_authentication=True
        ),
        SystemState.AUTHORIZED_IDLE: StateMetadata(
            name="AUTHORIZED_IDLE",
            description="Authenticated and ready for operations",
            allows_user_input=True,
            requires_network=False,
            requires_authentication=True
        ),
        SystemState.ENCRYPTING_DATA: StateMetadata(
            name="ENCRYPTING_DATA",
            description="Encrypting sensitive data",
            allows_user_input=False,
            requires_network=False,
            requires_authentication=True
        ),
        SystemState.ERROR: StateMetadata(
            name="ERROR",
            description="System error state requiring recovery",
            allows_user_input=True,
            requires_network=False,
            requires_authentication=False
        ),
        SystemState.SHUTDOWN: StateMetadata(
            name="SHUTDOWN",
            description="System shutdown state",
            is_terminal=True,
            allows_user_input=False,
            requires_network=False,
            requires_authentication=False
        ),
    }
    
    @classmethod
    def get_metadata(cls, state: SystemState) -> StateMetadata:
        """Get metadata for a given state."""
        return cls.METADATA.get(state)
    
    @classmethod
    def is_valid_state(cls, state: SystemState) -> bool:
        """Check if a state is valid and registered."""
        return state in cls.METADATA
    
    @classmethod
    def get_all_states(cls) -> Set[SystemState]:
        """Get all registered states."""
        return set(cls.METADATA.keys())

