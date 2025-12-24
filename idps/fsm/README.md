# Finite State Machine (FSM) Module

## Overview

This module implements a formal Finite State Machine for the IDPS application, ensuring the system **never enters an undefined state**. This is a critical requirement for academic-grade software where correctness and predictability are paramount.

## Architecture

The FSM module consists of five core components:

1. **States** (`states.py`): Defines explicit system states
2. **Transitions** (`transitions.py`): Formal transition rules
3. **Events** (`events.py`): Event system for triggering transitions
4. **Guards** (`guards.py`): Guard conditions for transition validation
5. **Controller** (`controller.py`): Async FSM controller with asyncio support

## State Definitions

The system defines the following states:

- **UNAUTHENTICATED**: Initial state, no user authentication
- **AUTHENTICATING**: Authentication process in progress
- **SYNCING**: Synchronizing data with remote server
- **AUTHORIZED_IDLE**: Authenticated and ready for operations
- **ENCRYPTING_DATA**: Encrypting sensitive data
- **ERROR**: Error state requiring recovery
- **SHUTDOWN**: Graceful shutdown state

Each state includes metadata:
- Whether it allows user input
- Whether it requires network connectivity
- Whether it requires authentication
- Whether it's a terminal state

## Transition Rules

Transitions are formally defined and validated. Invalid transitions are rejected, ensuring the system never enters an undefined state.

### Valid Transition Examples

```
UNAUTHENTICATED --[auth_requested]--> AUTHENTICATING
AUTHENTICATING --[auth_success]--> AUTHORIZED_IDLE
AUTHORIZED_IDLE --[sync_requested]--> SYNCING
SYNCING --[sync_complete]--> AUTHORIZED_IDLE
AUTHORIZED_IDLE --[encrypt_requested]--> ENCRYPTING_DATA
```

### Invalid Transitions (Rejected)

```
UNAUTHENTICATED --[sync_requested]--> SYNCING  ❌ (requires authentication)
AUTHENTICATING --[encrypt_requested]--> ENCRYPTING_DATA  ❌ (must be authorized)
```

## Event Handling

Events trigger state transitions. The system supports:

- **User Events**: Clicks, input, logout, shutdown
- **Authentication Events**: Success, failure, errors
- **Network Events**: Sync complete, errors, timeouts
- **Sensor Events**: Intrusion detection, sensor input
- **System Events**: Errors, recovery, timeouts

## Guard Conditions

Guard conditions enforce business logic constraints:

- `check_network_available`: Required for sync operations
- `check_has_data_to_encrypt`: Required before encryption
- `check_authenticated`: Required for authenticated operations

## Async Concurrency

The FSM controller uses Python's `asyncio` for non-blocking I/O:

- **Event Queue**: Events are queued and processed asynchronously
- **Non-blocking Transitions**: State changes don't block the UI thread
- **Concurrent Operations**: Multiple async operations can run simultaneously
- **Thread Safety**: Async locks ensure atomic state transitions

## Usage Example

```python
import asyncio
from idps.fsm import FSMController, SystemState, Event, EventType

async def main():
    # Initialize FSM
    fsm = FSMController(initial_state=SystemState.UNAUTHENTICATED)
    
    # Register state handlers
    async def on_authenticating(context):
        print("Authenticating...")
        await perform_authentication()
    
    fsm.register_state_handler(SystemState.AUTHENTICATING, on_authenticating)
    
    # Start FSM
    await fsm.start()
    
    # Send events
    auth_event = Event(
        event_type=EventType.AUTH_REQUESTED,
        source="ui",
        payload={"username": "admin"}
    )
    await fsm.send_event(auth_event)
    
    # Wait for processing
    await asyncio.sleep(1)
    
    print(f"Current state: {fsm.current_state.name}")
    
    await fsm.stop()

asyncio.run(main())
```

## Formal Correctness Guarantees

1. **State Validation**: All states are explicitly defined and validated
2. **Transition Validation**: Only valid transitions are allowed
3. **Guard Enforcement**: Business logic constraints are enforced
4. **Atomic Transitions**: State changes are atomic (protected by locks)
5. **History Tracking**: All transitions are logged for audit
6. **No Undefined States**: The system cannot enter an undefined state

## Visualization

Generate visual representations:

```python
from idps.fsm.visualization import save_visualization_files

# Save DOT graph and markdown tables
save_visualization_files("docs/fsm")
```

## Testing

Run the example usage:

```bash
python -m idps.fsm.example_usage
```

## Academic-Grade Features

- **Formal State Definitions**: Explicit enumeration of all states
- **Transition Rules**: Mathematically defined transition function
- **Guard Conditions**: Precondition checking
- **Event System**: Formal event-driven architecture
- **Concurrency Safety**: Async/await with proper locking
- **Audit Trail**: Complete state transition history
- **Visualization**: Graph and table representations

## Future Enhancements

- State machine persistence (save/restore state)
- Distributed FSM (multi-instance coordination)
- State machine testing framework
- Performance metrics and monitoring
- Advanced guard condition DSL

