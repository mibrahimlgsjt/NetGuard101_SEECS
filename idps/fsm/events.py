"""
Event System for FSM
Handles all events that trigger state transitions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any, Dict
from datetime import datetime
import uuid


class EventType(Enum):
    """Types of events that can trigger state transitions."""
    # User interaction events
    USER_CLICK = "user_click"
    USER_INPUT = "user_input"
    LOGOUT = "logout"
    
    # Authentication events
    AUTH_REQUESTED = "auth_requested"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILED = "auth_failed"
    AUTH_ERROR = "auth_error"
    
    # Network events
    SYNC_REQUESTED = "sync_requested"
    SYNC_COMPLETE = "sync_complete"
    SYNC_ERROR = "sync_error"
    SYNC_TIMEOUT = "sync_timeout"
    NETWORK_AVAILABLE = "network_available"
    NETWORK_UNAVAILABLE = "network_unavailable"
    
    # Data operations
    ENCRYPT_REQUESTED = "encrypt_requested"
    ENCRYPT_COMPLETE = "encrypt_complete"
    ENCRYPT_ERROR = "encrypt_error"
    
    # Sensor events
    SENSOR_INPUT = "sensor_input"
    INTRUSION_DETECTED = "intrusion_detected"
    
    # System events
    SHUTDOWN_REQUESTED = "shutdown_requested"
    ERROR_RECOVERED = "error_recovered"
    TIMEOUT = "timeout"


@dataclass
class Event:
    """
    Represents an event that can trigger a state transition.
    Events are immutable and contain all necessary context.
    """
    event_type: EventType
    timestamp: datetime = field(default_factory=datetime.now)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "unknown"  # Where the event originated
    payload: Dict[str, Any] = field(default_factory=dict)
    
    def __repr__(self) -> str:
        return f"Event({self.event_type.value}, source={self.source}, id={self.event_id[:8]})"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "source": self.source,
            "payload": self.payload
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        """Create event from dictionary."""
        return cls(
            event_type=EventType(data["event_type"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            event_id=data["event_id"],
            source=data["source"],
            payload=data.get("payload", {})
        )


class EventHandler:
    """
    Base class for event handlers.
    Handlers process events and determine if state transitions should occur.
    """
    
    def can_handle(self, event: Event) -> bool:
        """Check if this handler can process the given event."""
        raise NotImplementedError
    
    async def handle(self, event: Event, current_state, context: Dict[str, Any]) -> Optional[str]:
        """
        Process an event and return the event type string for transition.
        
        Args:
            event: The event to process
            current_state: Current system state
            context: Additional context (e.g., network status, auth status)
            
        Returns:
            Event type string for transition, or None if no transition needed
        """
        raise NotImplementedError


class UserEventHandler(EventHandler):
    """Handles user interaction events."""
    
    def can_handle(self, event: Event) -> bool:
        return event.event_type in [
            EventType.USER_CLICK,
            EventType.USER_INPUT,
            EventType.LOGOUT,
            EventType.AUTH_REQUESTED,
            EventType.SYNC_REQUESTED,
            EventType.ENCRYPT_REQUESTED,
            EventType.SHUTDOWN_REQUESTED
        ]
    
    async def handle(self, event: Event, current_state, context: Dict[str, Any]) -> Optional[str]:
        """Map user events to transition event types."""
        event_mapping = {
            EventType.AUTH_REQUESTED: "auth_requested",
            EventType.SYNC_REQUESTED: "sync_requested",
            EventType.ENCRYPT_REQUESTED: "encrypt_requested",
            EventType.LOGOUT: "logout",
            EventType.SHUTDOWN_REQUESTED: "shutdown_requested"
        }
        return event_mapping.get(event.event_type)


class NetworkEventHandler(EventHandler):
    """Handles network-related events."""
    
    def can_handle(self, event: Event) -> bool:
        return event.event_type in [
            EventType.SYNC_COMPLETE,
            EventType.SYNC_ERROR,
            EventType.SYNC_TIMEOUT,
            EventType.NETWORK_AVAILABLE,
            EventType.NETWORK_UNAVAILABLE
        ]
    
    async def handle(self, event: Event, current_state, context: Dict[str, Any]) -> Optional[str]:
        """Map network events to transition event types."""
        event_mapping = {
            EventType.SYNC_COMPLETE: "sync_complete",
            EventType.SYNC_ERROR: "sync_error",
            EventType.SYNC_TIMEOUT: "sync_timeout"
        }
        return event_mapping.get(event.event_type)


class AuthenticationEventHandler(EventHandler):
    """Handles authentication events."""
    
    def can_handle(self, event: Event) -> bool:
        return event.event_type in [
            EventType.AUTH_SUCCESS,
            EventType.AUTH_FAILED,
            EventType.AUTH_ERROR
        ]
    
    async def handle(self, event: Event, current_state, context: Dict[str, Any]) -> Optional[str]:
        """Map authentication events to transition event types."""
        event_mapping = {
            EventType.AUTH_SUCCESS: "auth_success",
            EventType.AUTH_FAILED: "auth_failed",
            EventType.AUTH_ERROR: "auth_error"
        }
        return event_mapping.get(event.event_type)


class SensorEventHandler(EventHandler):
    """Handles sensor input events."""
    
    def can_handle(self, event: Event) -> bool:
        return event.event_type in [
            EventType.SENSOR_INPUT,
            EventType.INTRUSION_DETECTED
        ]
    
    async def handle(self, event: Event, current_state, context: Dict[str, Any]) -> Optional[str]:
        """Process sensor events - may trigger encryption or alerts."""
        if event.event_type == EventType.INTRUSION_DETECTED:
            # Intrusion detected might trigger encryption
            if current_state.name == "AUTHORIZED_IDLE":
                return "encrypt_requested"
        return None


class EventProcessor:
    """
    Processes events through registered handlers.
    Determines which events should trigger state transitions.
    """
    
    def __init__(self):
        self.handlers: list[EventHandler] = [
            UserEventHandler(),
            NetworkEventHandler(),
            AuthenticationEventHandler(),
            SensorEventHandler()
        ]
    
    async def process_event(
        self,
        event: Event,
        current_state,
        context: Dict[str, Any]
    ) -> Optional[str]:
        """
        Process an event through all applicable handlers.
        
        Returns:
            Event type string for transition, or None
        """
        for handler in self.handlers:
            if handler.can_handle(event):
                result = await handler.handle(event, current_state, context)
                if result:
                    return result
        return None

