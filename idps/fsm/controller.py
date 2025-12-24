"""
Async Finite State Machine Controller
Main controller that manages state transitions using asyncio for non-blocking I/O.
"""

import asyncio
from typing import Optional, Dict, Any, Callable, Set
from datetime import datetime
from collections import deque
import logging

from idps.fsm.states import SystemState, StateRegistry
from idps.fsm.transitions import TransitionRules, TransitionResult
from idps.fsm.events import Event, EventProcessor
from idps.fsm.guards import guard_conditions


logger = logging.getLogger(__name__)


class StateTransitionError(Exception):
    """Raised when an invalid state transition is attempted."""
    pass


class FSMController:
    """
    Async Finite State Machine Controller
    
    Manages state transitions, event processing, and ensures the system
    never enters an undefined state. Uses asyncio for non-blocking I/O.
    """
    
    def __init__(self, initial_state: SystemState = SystemState.UNAUTHENTICATED):
        """
        Initialize the FSM controller.
        
        Args:
            initial_state: Starting state of the system
        """
        self._current_state = initial_state
        self._previous_state: Optional[SystemState] = None
        self._state_history: deque = deque(maxlen=100)  # Keep last 100 transitions
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._event_processor = EventProcessor()
        self._context: Dict[str, Any] = {
            "network_available": False,
            "is_authenticated": False,
            "has_data_to_encrypt": False,
            "last_transition_time": None
        }
        self._state_handlers: Dict[SystemState, Callable] = {}
        self._transition_callbacks: list[Callable] = []
        self._running = False
        self._lock = asyncio.Lock()
        
        # Validate initial state
        if not StateRegistry.is_valid_state(initial_state):
            raise ValueError(f"Invalid initial state: {initial_state}")
        
        logger.info(f"FSM Controller initialized with state: {initial_state.name}")
    
    @property
    def current_state(self) -> SystemState:
        """Get the current system state."""
        return self._current_state
    
    @property
    def previous_state(self) -> Optional[SystemState]:
        """Get the previous system state."""
        return self._previous_state
    
    def get_state_history(self) -> list[tuple[SystemState, datetime]]:
        """Get the state transition history."""
        return list(self._state_history)
    
    def register_state_handler(
        self,
        state: SystemState,
        handler: Callable[[Dict[str, Any]], None]
    ):
        """
        Register a handler function to be called when entering a state.
        
        Args:
            state: The state to handle
            handler: Async function to call when entering the state
        """
        self._state_handlers[state] = handler
    
    def register_transition_callback(
        self,
        callback: Callable[[SystemState, SystemState, str], None]
    ):
        """
        Register a callback to be called on every state transition.
        
        Args:
            callback: Async function(state_from, state_to, event_type)
        """
        self._transition_callbacks.append(callback)
    
    async def transition(
        self,
        target_state: SystemState,
        event_type: str,
        context_update: Optional[Dict[str, Any]] = None
    ) -> TransitionResult:
        """
        Attempt to transition to a new state.
        
        This is the core method that enforces formal correctness.
        It validates the transition, checks guards, and updates state atomically.
        
        Args:
            target_state: The state to transition to
            event_type: Type of event triggering the transition
            context_update: Optional context updates
            
        Returns:
            TransitionResult indicating success or failure reason
        """
        async with self._lock:
            # Update context if provided
            if context_update:
                self._context.update(context_update)
            
            # Check if already in target state
            if self._current_state == target_state:
                return TransitionResult.ALREADY_IN_STATE
            
            # Validate transition
            if not TransitionRules.is_valid_transition(
                self._current_state,
                target_state,
                event_type
            ):
                logger.warning(
                    f"Invalid transition: {self._current_state.name} --[{event_type}]--> "
                    f"{target_state.name}"
                )
                return TransitionResult.INVALID_TRANSITION
            
            # Check guard conditions
            guard_name = TransitionRules.get_guard_condition(
                self._current_state,
                target_state,
                event_type
            )
            if guard_name:
                guard_passed = await guard_conditions.check_guard(
                    guard_name,
                    self._context
                )
                if not guard_passed:
                    logger.warning(
                        f"Guard condition '{guard_name}' failed for transition "
                        f"{self._current_state.name} -> {target_state.name}"
                    )
                    return TransitionResult.GUARD_FAILED
            
            # Perform transition
            from_state = self._current_state
            self._previous_state = from_state
            self._current_state = target_state
            self._context["last_transition_time"] = datetime.now()
            
            # Record in history
            self._state_history.append((target_state, datetime.now()))
            
            logger.info(
                f"State transition: {from_state.name} --[{event_type}]--> "
                f"{target_state.name}"
            )
            
            # Call transition callbacks
            for callback in self._transition_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(from_state, target_state, event_type)
                    else:
                        callback(from_state, target_state, event_type)
                except Exception as e:
                    logger.error(f"Error in transition callback: {e}")
            
            # Call state handler
            if target_state in self._state_handlers:
                handler = self._state_handlers[target_state]
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(self._context)
                    else:
                        handler(self._context)
                except Exception as e:
                    logger.error(f"Error in state handler for {target_state.name}: {e}")
            
            return TransitionResult.SUCCESS
    
    async def process_event(self, event: Event) -> TransitionResult:
        """
        Process an event and trigger appropriate state transition.
        
        This method processes events asynchronously, ensuring UI remains responsive.
        
        Args:
            event: The event to process
            
        Returns:
            TransitionResult indicating success or failure
        """
        # Process event through handlers
        transition_event_type = await self._event_processor.process_event(
            event,
            self._current_state,
            self._context
        )
        
        if not transition_event_type:
            # Event didn't trigger a transition
            return TransitionResult.INVALID_TRANSITION
        
        # Find valid target state for this event
        valid_targets = TransitionRules.get_valid_targets(
            self._current_state,
            transition_event_type
        )
        
        if not valid_targets:
            logger.warning(
                f"No valid target states for event '{transition_event_type}' "
                f"from state '{self._current_state.name}'"
            )
            return TransitionResult.INVALID_TRANSITION
        
        # For now, take the first valid target (could be enhanced with priority)
        target_state = next(iter(valid_targets))
        
        # Perform transition
        return await self.transition(target_state, transition_event_type)
    
    async def send_event(self, event: Event):
        """
        Send an event to the FSM (non-blocking).
        Events are queued and processed asynchronously.
        
        Args:
            event: The event to send
        """
        await self._event_queue.put(event)
    
    async def start(self):
        """Start the FSM event processing loop."""
        if self._running:
            return
        
        self._running = True
        logger.info("FSM Controller started")
        
        # Start event processing loop
        asyncio.create_task(self._event_loop())
    
    async def stop(self):
        """Stop the FSM event processing loop."""
        self._running = False
        logger.info("FSM Controller stopped")
    
    async def _event_loop(self):
        """Main event processing loop (runs asynchronously)."""
        while self._running:
            try:
                # Wait for event with timeout to allow periodic checks
                event = await asyncio.wait_for(
                    self._event_queue.get(),
                    timeout=1.0
                )
                
                # Process event
                result = await self.process_event(event)
                
                if result != TransitionResult.SUCCESS:
                    logger.debug(
                        f"Event {event.event_id[:8]} did not trigger transition: {result.value}"
                    )
                
            except asyncio.TimeoutError:
                # Timeout is expected, continue loop
                continue
            except Exception as e:
                logger.error(f"Error in FSM event loop: {e}", exc_info=True)
    
    def update_context(self, updates: Dict[str, Any]):
        """
        Update the FSM context synchronously.
        Use this for updating system state that doesn't require transitions.
        
        Args:
            updates: Dictionary of context updates
        """
        self._context.update(updates)
    
    def get_context(self) -> Dict[str, Any]:
        """Get a copy of the current context."""
        return self._context.copy()
    
    def get_valid_transitions(self) -> Set[SystemState]:
        """
        Get all valid target states from the current state.
        Useful for UI to show available actions.
        
        Returns:
            Set of valid target states
        """
        return TransitionRules.get_valid_targets(self._current_state)
    
    def can_transition_to(self, target_state: SystemState, event_type: str) -> bool:
        """
        Check if a transition to target_state is valid.
        
        Args:
            target_state: Target state to check
            event_type: Event type for the transition
            
        Returns:
            True if transition is valid
        """
        return TransitionRules.is_valid_transition(
            self._current_state,
            target_state,
            event_type
        )

