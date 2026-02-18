"""
Consolidated Chat Agent for IDPS
Unified interface for interacting with all project components:
- FSM Controller (Python backend)
- Network layers (Android/Kotlin)
- Security monitoring
- System state management
"""

import asyncio
import json
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from enum import Enum
import logging

from idps.fsm.controller import FSMController, StateTransitionError
from idps.fsm.states import SystemState, StateRegistry
from idps.fsm.events import Event, EventType
from idps.fsm.transitions import TransitionRules, TransitionResult

logger = logging.getLogger(__name__)


class ChatAgentResponse:
    """Structured response from the chat agent."""
    
    def __init__(
        self,
        message: str,
        success: bool = True,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        self.message = message
        self.success = success
        self.data = data or {}
        self.error = error
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary."""
        return {
            "message": self.message,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "timestamp": self.timestamp.isoformat()
        }
    
    def __str__(self) -> str:
        if self.success:
            return f"✓ {self.message}"
        else:
            return f"✗ {self.message}: {self.error}"


class ChatAgent:
    """
    Consolidated Chat Agent for IDPS
    
    Provides a unified interface to interact with:
    - FSM Controller (state management)
    - Network monitoring
    - Security events
    - System status
    - Android app integration
    """
    
    def __init__(self, fsm_controller: Optional[FSMController] = None):
        """
        Initialize the chat agent.
        
        Args:
            fsm_controller: Optional FSM controller instance. If None, creates a new one.
        """
        self.fsm = fsm_controller or FSMController()
        self._conversation_history: List[Dict[str, Any]] = []
        self._network_stats: Dict[str, Any] = {
            "packets_analyzed": 0,
            "threats_detected": 0,
            "network_status": "unknown",
            "last_activity": None
        }
        self._android_status: Dict[str, Any] = {
            "connected": False,
            "session_state": "unknown",
            "circuit_breaker_state": "unknown"
        }
        
        # Start FSM if not already running
        asyncio.create_task(self._ensure_fsm_running())
    
    async def _ensure_fsm_running(self):
        """Ensure FSM controller is running."""
        try:
            await self.fsm.start()
        except Exception as e:
            logger.warning(f"FSM already running or error: {e}")
    
    async def process_query(self, query: str) -> ChatAgentResponse:
        """
        Process a user query and return a response.
        
        Args:
            query: User's query string
            
        Returns:
            ChatAgentResponse with answer and relevant data
        """
        query_lower = query.lower().strip()
        
        # Add to conversation history
        self._conversation_history.append({
            "query": query,
            "timestamp": datetime.now().isoformat()
        })
        
        # Route query to appropriate handler
        try:
            # System state queries
            if any(keyword in query_lower for keyword in ["state", "status", "current"]):
                return await self._handle_state_query(query)
            
            # FSM/transition queries
            elif any(keyword in query_lower for keyword in ["transition", "change state", "move to"]):
                return await self._handle_transition_query(query)
            
            # Network queries
            elif any(keyword in query_lower for keyword in ["network", "packet", "traffic", "connection"]):
                return await self._handle_network_query(query)
            
            # Security/threat queries
            elif any(keyword in query_lower for keyword in ["threat", "intrusion", "alert", "security"]):
                return await self._handle_security_query(query)
            
            # Android app queries
            elif any(keyword in query_lower for keyword in ["android", "app", "mobile", "kotlin"]):
                return await self._handle_android_query(query)
            
            # Event queries
            elif any(keyword in query_lower for keyword in ["event", "trigger", "send"]):
                return await self._handle_event_query(query)
            
            # History queries
            elif any(keyword in query_lower for keyword in ["history", "log", "past", "previous"]):
                return await self._handle_history_query(query)
            
            # Help queries
            elif any(keyword in query_lower for keyword in ["help", "what can", "capabilities", "commands"]):
                return await self._handle_help_query()
            
            # Default: general information
            else:
                return await self._handle_general_query(query)
        
        except Exception as e:
            logger.error(f"Error processing query: {e}", exc_info=True)
            return ChatAgentResponse(
                message="An error occurred while processing your query",
                success=False,
                error=str(e)
            )
    
    async def _handle_state_query(self, query: str) -> ChatAgentResponse:
        """Handle queries about system state."""
        current_state = self.fsm.current_state
        previous_state = self.fsm.previous_state
        context = self.fsm.get_context()
        state_metadata = StateRegistry.get_metadata(current_state)
        
        # Get valid transitions
        valid_transitions = self.fsm.get_valid_transitions()
        
        response_data = {
            "current_state": current_state.name,
            "state_description": state_metadata.description,
            "previous_state": previous_state.name if previous_state else None,
            "allows_user_input": state_metadata.allows_user_input,
            "requires_network": state_metadata.requires_network,
            "requires_authentication": state_metadata.requires_authentication,
            "context": context,
            "valid_transitions": [state.name for state in valid_transitions]
        }
        
        message = (
            f"Current System State: {current_state.name}\n"
            f"Description: {state_metadata.description}\n"
            f"Previous State: {previous_state.name if previous_state else 'N/A'}\n"
            f"Valid Transitions: {', '.join([s.name for s in valid_transitions])}"
        )
        
        return ChatAgentResponse(
            message=message,
            success=True,
            data=response_data
        )
    
    async def _handle_transition_query(self, query: str) -> ChatAgentResponse:
        """Handle queries about state transitions."""
        query_lower = query.lower()
        current_state = self.fsm.current_state
        
        # Try to extract target state from query
        target_state = None
        for state in SystemState:
            state_name_lower = state.name.lower().replace("_", " ")
            if state_name_lower in query_lower or state.name.lower() in query_lower:
                target_state = state
                break
        
        if not target_state:
            # List all possible transitions with event types
            valid_transitions = self.fsm.get_valid_transitions()
            
            # Get detailed transition info
            transition_details = []
            for target in valid_transitions:
                # Find event types that allow this transition
                for event_type in ["auth_requested", "auth_success", "sync_requested", 
                                 "sync_complete", "encrypt_requested", "encrypt_complete",
                                 "logout", "shutdown_requested", "error_recovered"]:
                    if self.fsm.can_transition_to(target, event_type):
                        transition_details.append(f"  - {target.name} (via {event_type})")
                        break
            
            message = (
                f"From {current_state.name}, you can transition to:\n"
                + "\n".join(transition_details) if transition_details
                else f"  No valid transitions available from {current_state.name}"
            )
            
            return ChatAgentResponse(
                message=message,
                success=True,
                data={
                    "current_state": current_state.name,
                    "valid_transitions": [s.name for s in valid_transitions]
                }
            )
        
        # Check if transition is valid and find event type
        # Check all possible event types
        valid_event = None
        all_event_types = [
            "auth_requested", "auth_success", "auth_failed", "auth_error",
            "sync_requested", "sync_complete", "sync_error", "sync_timeout",
            "encrypt_requested", "encrypt_complete", "encrypt_error",
            "logout", "shutdown_requested", "error_recovered"
        ]
        
        for event_type in all_event_types:
            if self.fsm.can_transition_to(target_state, event_type):
                valid_event = event_type
                break
        
        if not valid_event:
            # Try to find a path using TransitionRules
            from idps.fsm.transitions import TransitionRules
            path = TransitionRules.get_transition_path(current_state, target_state)
            
            if path:
                path_info = "\n".join([f"  {i+1}. {t}" for i, t in enumerate(path)])
                return ChatAgentResponse(
                    message=(
                        f"Multi-step path from {current_state.name} to {target_state.name}:\n"
                        + path_info
                    ),
                    success=True,
                    data={"path": [str(t) for t in path]}
                )
            else:
                return ChatAgentResponse(
                    message=f"Cannot transition from {current_state.name} to {target_state.name}",
                    success=False,
                    error="No valid transition path found"
                )
        
        # Attempt transition
        try:
            result = await self.fsm.transition(target_state, valid_event)
            
            if result == TransitionResult.SUCCESS:
                return ChatAgentResponse(
                    message=f"Successfully transitioned from {current_state.name} to {target_state.name}",
                    success=True,
                    data={
                        "from_state": current_state.name,
                        "to_state": target_state.name,
                        "event_type": valid_event
                    }
                )
            else:
                return ChatAgentResponse(
                    message=f"Transition failed: {result.value}",
                    success=False,
                    error=result.value
                )
        except Exception as e:
            return ChatAgentResponse(
                message="Transition error occurred",
                success=False,
                error=str(e)
            )
    
    async def _handle_network_query(self, query: str) -> ChatAgentResponse:
        """Handle queries about network status."""
        context = self.fsm.get_context()
        network_available = context.get("network_available", False)
        
        response_data = {
            "network_available": network_available,
            "packets_analyzed": self._network_stats["packets_analyzed"],
            "threats_detected": self._network_stats["threats_detected"],
            "network_status": "active" if network_available else "inactive",
            "last_activity": self._network_stats["last_activity"]
        }
        
        message = (
            f"Network Status: {'Active' if network_available else 'Inactive'}\n"
            f"Packets Analyzed: {self._network_stats['packets_analyzed']}\n"
            f"Threats Detected: {self._network_stats['threats_detected']}"
        )
        
        return ChatAgentResponse(
            message=message,
            success=True,
            data=response_data
        )
    
    async def _handle_security_query(self, query: str) -> ChatAgentResponse:
        """Handle queries about security and threats."""
        threats = self._network_stats["threats_detected"]
        current_state = self.fsm.current_state
        
        # Determine threat level
        threat_level = "LOW"
        if threats > 10:
            threat_level = "HIGH"
        elif threats > 5:
            threat_level = "MEDIUM"
        
        response_data = {
            "threat_level": threat_level,
            "threats_detected": threats,
            "system_state": current_state.name,
            "is_secure": current_state in [SystemState.AUTHORIZED_IDLE, SystemState.ENCRYPTING_DATA]
        }
        
        message = (
            f"Security Status:\n"
            f"Threat Level: {threat_level}\n"
            f"Threats Detected: {threats}\n"
            f"System State: {current_state.name}\n"
            f"Security Status: {'Secure' if response_data['is_secure'] else 'Needs Attention'}"
        )
        
        return ChatAgentResponse(
            message=message,
            success=True,
            data=response_data
        )
    
    async def _handle_android_query(self, query: str) -> ChatAgentResponse:
        """Handle queries about Android app status."""
        response_data = {
            "android_app_connected": self._android_status["connected"],
            "session_state": self._android_status["session_state"],
            "circuit_breaker_state": self._android_status["circuit_breaker_state"],
            "components": [
                "ApplicationLayer (RESTful API)",
                "SessionLayer (JWT Token Management)",
                "TransportLayerSecurity (TLS 1.3)",
                "ReliabilityLayer (Circuit Breaker)"
            ]
        }
        
        message = (
            f"Android App Status:\n"
            f"Connected: {self._android_status['connected']}\n"
            f"Session State: {self._android_status['session_state']}\n"
            f"Circuit Breaker: {self._android_status['circuit_breaker_state']}\n"
            f"\nComponents:\n"
            + "\n".join([f"  - {comp}" for comp in response_data["components"]])
        )
        
        return ChatAgentResponse(
            message=message,
            success=True,
            data=response_data
        )
    
    async def _handle_event_query(self, query: str) -> ChatAgentResponse:
        """Handle queries about sending events."""
        query_lower = query.lower()
        
        # Try to identify event type
        event_type = None
        for et in EventType:
            if et.value.replace("_", " ") in query_lower or et.name.lower() in query_lower:
                event_type = et
                break
        
        if not event_type:
            # List available events
            available_events = [et.value for et in EventType]
            return ChatAgentResponse(
                message=(
                    "Available Event Types:\n"
                    + "\n".join([f"  - {ev}" for ev in available_events])
                ),
                success=True,
                data={"available_events": available_events}
            )
        
        # Create and send event
        event = Event(
            event_type=event_type,
            source="chat_agent",
            payload={"query": query}
        )
        
        try:
            await self.fsm.send_event(event)
            
            return ChatAgentResponse(
                message=f"Event '{event_type.value}' sent successfully",
                success=True,
                data={
                    "event_type": event_type.value,
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat()
                }
            )
        except Exception as e:
            return ChatAgentResponse(
                message="Failed to send event",
                success=False,
                error=str(e)
            )
    
    async def _handle_history_query(self, query: str) -> ChatAgentResponse:
        """Handle queries about system history."""
        state_history = self.fsm.get_state_history()
        conversation_count = len(self._conversation_history)
        
        # Format state history
        history_text = []
        for state, timestamp in state_history[-10:]:  # Last 10 transitions
            history_text.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')}: {state.name}")
        
        response_data = {
            "state_transitions": len(state_history),
            "conversation_count": conversation_count,
            "recent_transitions": [
                {"state": state.name, "timestamp": ts.isoformat()}
                for state, ts in state_history[-10:]
            ]
        }
        
        message = (
            f"System History:\n"
            f"Total State Transitions: {len(state_history)}\n"
            f"Conversation Queries: {conversation_count}\n"
            f"\nRecent Transitions:\n"
            + "\n".join(history_text) if history_text else "No transitions yet"
        )
        
        return ChatAgentResponse(
            message=message,
            success=True,
            data=response_data
        )
    
    async def _handle_help_query(self) -> ChatAgentResponse:
        """Handle help queries."""
        help_text = """
IDPS Chat Agent - Available Commands:

STATE QUERIES:
  - "What is the current state?"
  - "Show system status"
  - "What states are available?"

TRANSITION QUERIES:
  - "Transition to AUTHORIZED_IDLE"
  - "Change state to SYNCING"
  - "What transitions are possible?"

NETWORK QUERIES:
  - "Network status"
  - "How many packets analyzed?"
  - "Show network statistics"

SECURITY QUERIES:
  - "Security status"
  - "Any threats detected?"
  - "Show threat level"

ANDROID QUERIES:
  - "Android app status"
  - "Show mobile app components"
  - "Kotlin networking status"

EVENT QUERIES:
  - "Send auth_requested event"
  - "Trigger sync_requested"
  - "What events are available?"

HISTORY QUERIES:
  - "Show history"
  - "Previous states"
  - "Conversation log"

GENERAL:
  - Ask any question about the IDPS system
  - Query FSM controller state
  - Monitor network and security status
        """
        
        return ChatAgentResponse(
            message=help_text.strip(),
            success=True,
            data={"capabilities": [
                "State Management",
                "Network Monitoring",
                "Security Analysis",
                "Event Handling",
                "History Tracking",
                "Android Integration"
            ]}
        )
    
    async def _handle_general_query(self, query: str) -> ChatAgentResponse:
        """Handle general queries."""
        # Provide general system information
        current_state = self.fsm.current_state
        context = self.fsm.get_context()
        
        message = (
            f"IDPS System Information:\n"
            f"Current State: {current_state.name}\n"
            f"Network Available: {context.get('network_available', False)}\n"
            f"Authenticated: {context.get('is_authenticated', False)}\n"
            f"\nFor more specific information, try:\n"
            f"  - 'help' for available commands\n"
            f"  - 'state' for detailed state information\n"
            f"  - 'network' for network statistics\n"
            f"  - 'security' for security status"
        )
        
        return ChatAgentResponse(
            message=message,
            success=True,
            data={
                "current_state": current_state.name,
                "context": context
            }
        )
    
    def update_network_stats(self, **kwargs):
        """Update network statistics."""
        self._network_stats.update(kwargs)
        self._network_stats["last_activity"] = datetime.now().isoformat()
    
    def update_android_status(self, **kwargs):
        """Update Android app status."""
        self._android_status.update(kwargs)
    
    def get_conversation_history(self) -> List[Dict[str, Any]]:
        """Get conversation history."""
        return self._conversation_history.copy()
    
    async def shutdown(self):
        """Shutdown the chat agent and FSM."""
        await self.fsm.stop()


# Convenience function for interactive use
async def interactive_chat():
    """Interactive chat interface."""
    agent = ChatAgent()
    print("IDPS Chat Agent - Type 'exit' to quit, 'help' for commands\n")
    
    while True:
        try:
            query = input("You: ").strip()
            if not query:
                continue
            
            if query.lower() in ["exit", "quit", "q"]:
                print("Goodbye!")
                await agent.shutdown()
                break
            
            response = await agent.process_query(query)
            print(f"\nAgent: {response.message}\n")
            
            if response.data:
                print(f"Data: {json.dumps(response.data, indent=2)}\n")
        
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            await agent.shutdown()
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    # Run interactive chat
    asyncio.run(interactive_chat())

