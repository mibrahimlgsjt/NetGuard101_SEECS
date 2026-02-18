"""
Example usage of the FSM Controller
Demonstrates how to use the Finite State Machine for IDPS.
"""

import asyncio
import logging
from idps.fsm import (
    FSMController,
    SystemState,
    Event,
    EventType
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def state_handler_authenticating(context):
    """Handler for AUTHENTICATING state."""
    logger.info("Entering AUTHENTICATING state - simulating authentication...")
    await asyncio.sleep(1)  # Simulate async auth operation
    logger.info("Authentication complete")


async def state_handler_syncing(context):
    """Handler for SYNCING state."""
    logger.info("Entering SYNCING state - syncing with server...")
    await asyncio.sleep(2)  # Simulate async sync operation
    logger.info("Sync complete")


async def state_handler_encrypting(context):
    """Handler for ENCRYPTING_DATA state."""
    logger.info("Entering ENCRYPTING_DATA state - encrypting sensitive data...")
    await asyncio.sleep(1.5)  # Simulate async encryption
    logger.info("Encryption complete")


async def transition_callback(from_state, to_state, event_type):
    """Callback for state transitions."""
    logger.info(f"Transition callback: {from_state.name} -> {to_state.name} via {event_type}")


async def main():
    """Main example demonstrating FSM usage."""
    # Initialize FSM controller
    fsm = FSMController(initial_state=SystemState.UNAUTHENTICATED)
    
    # Register state handlers
    fsm.register_state_handler(SystemState.AUTHENTICATING, state_handler_authenticating)
    fsm.register_state_handler(SystemState.SYNCING, state_handler_syncing)
    fsm.register_state_handler(SystemState.ENCRYPTING_DATA, state_handler_encrypting)
    
    # Register transition callback
    fsm.register_transition_callback(transition_callback)
    
    # Update context (e.g., network available)
    fsm.update_context({
        "network_available": True,
        "has_data_to_encrypt": True
    })
    
    # Start the FSM
    await fsm.start()
    
    logger.info(f"Initial state: {fsm.current_state.name}")
    
    # Example 1: Authentication flow
    logger.info("\n=== Example 1: Authentication Flow ===")
    auth_event = Event(
        event_type=EventType.AUTH_REQUESTED,
        source="ui",
        payload={"username": "admin"}
    )
    await fsm.send_event(auth_event)
    await asyncio.sleep(0.5)  # Wait for event processing
    
    # Simulate authentication success
    auth_success_event = Event(
        event_type=EventType.AUTH_SUCCESS,
        source="auth_service",
        payload={"user_id": "123"}
    )
    await fsm.send_event(auth_success_event)
    await asyncio.sleep(0.5)
    
    logger.info(f"Current state after auth: {fsm.current_state.name}")
    
    # Example 2: Sync operation
    logger.info("\n=== Example 2: Sync Operation ===")
    sync_event = Event(
        event_type=EventType.SYNC_REQUESTED,
        source="ui",
        payload={"sync_type": "full"}
    )
    await fsm.send_event(sync_event)
    await asyncio.sleep(0.5)
    
    logger.info(f"Current state during sync: {fsm.current_state.name}")
    
    # Simulate sync completion
    sync_complete_event = Event(
        event_type=EventType.SYNC_COMPLETE,
        source="sync_service",
        payload={"items_synced": 42}
    )
    await fsm.send_event(sync_complete_event)
    await asyncio.sleep(0.5)
    
    logger.info(f"Current state after sync: {fsm.current_state.name}")
    
    # Example 3: Encryption operation
    logger.info("\n=== Example 3: Encryption Operation ===")
    encrypt_event = Event(
        event_type=EventType.ENCRYPT_REQUESTED,
        source="data_service",
        payload={"data_size": 1024}
    )
    await fsm.send_event(encrypt_event)
    await asyncio.sleep(0.5)
    
    logger.info(f"Current state during encryption: {fsm.current_state.name}")
    
    # Simulate encryption completion
    encrypt_complete_event = Event(
        event_type=EventType.ENCRYPT_COMPLETE,
        source="crypto_service",
        payload={"encrypted_size": 2048}
    )
    await fsm.send_event(encrypt_complete_event)
    await asyncio.sleep(0.5)
    
    logger.info(f"Current state after encryption: {fsm.current_state.name}")
    
    # Example 4: Invalid transition attempt
    logger.info("\n=== Example 4: Invalid Transition Attempt ===")
    invalid_event = Event(
        event_type=EventType.SYNC_REQUESTED,
        source="ui",
        payload={}
    )
    # This should fail because we're already in AUTHORIZED_IDLE, not UNAUTHENTICATED
    result = await fsm.process_event(invalid_event)
    logger.info(f"Transition result: {result.value}")
    
    # Show state history
    logger.info("\n=== State History ===")
    history = fsm.get_state_history()
    for state, timestamp in history:
        logger.info(f"  {timestamp.strftime('%H:%M:%S')} - {state.name}")
    
    # Show valid transitions from current state
    logger.info("\n=== Valid Transitions from Current State ===")
    valid_targets = fsm.get_valid_transitions()
    for target in valid_targets:
        logger.info(f"  Can transition to: {target.name}")
    
    # Stop the FSM
    await fsm.stop()
    logger.info("\nFSM stopped")


if __name__ == "__main__":
    asyncio.run(main())

