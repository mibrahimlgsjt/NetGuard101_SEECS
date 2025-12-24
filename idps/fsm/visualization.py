"""
FSM Visualization Tools
Generate visual representations of the state machine for documentation.
"""

from typing import Dict, Set
from idps.fsm.states import SystemState
from idps.fsm.transitions import TransitionRules


def generate_dot_graph() -> str:
    """
    Generate Graphviz DOT format representation of the FSM.
    
    Returns:
        DOT format string that can be rendered with Graphviz
    """
    lines = ["digraph FSM {", "  rankdir=LR;", "  node [shape=box, style=rounded];", ""]
    
    # Add nodes (states)
    for state in SystemState:
        metadata = StateRegistry.get_metadata(state)
        color = "lightblue" if state == SystemState.UNAUTHENTICATED else "lightgray"
        if state == SystemState.SHUTDOWN:
            color = "lightcoral"
        elif state == SystemState.ERROR:
            color = "lightyellow"
        
        lines.append(f'  {state.name} [label="{state.name}\\n{metadata.description}", fillcolor={color}, style="filled,rounded"];')
    
    lines.append("")
    
    # Add edges (transitions)
    transitions_by_event: Dict[str, Set[tuple[SystemState, SystemState]]] = {}
    for from_state, to_state, event_type in TransitionRules.VALID_TRANSITIONS:
        if event_type not in transitions_by_event:
            transitions_by_event[event_type] = set()
        transitions_by_event[event_type].add((from_state, to_state))
    
    for event_type, transitions in transitions_by_event.items():
        for from_state, to_state in transitions:
            lines.append(f'  {from_state.name} -> {to_state.name} [label="{event_type}"];')
    
    lines.append("}")
    return "\n".join(lines)


def generate_state_table() -> str:
    """
    Generate a markdown table of all states and their metadata.
    
    Returns:
        Markdown formatted table
    """
    lines = [
        "| State | Description | Allows Input | Requires Network | Requires Auth |",
        "|-------|-------------|--------------|------------------|---------------|"
    ]
    
    for state in SystemState:
        metadata = StateRegistry.get_metadata(state)
        lines.append(
            f"| {state.name} | {metadata.description} | "
            f"{'Yes' if metadata.allows_user_input else 'No'} | "
            f"{'Yes' if metadata.requires_network else 'No'} | "
            f"{'Yes' if metadata.requires_authentication else 'No'} |"
        )
    
    return "\n".join(lines)


def generate_transition_table() -> str:
    """
    Generate a markdown table of all valid transitions.
    
    Returns:
        Markdown formatted table
    """
    lines = [
        "| From State | To State | Event Type | Guard Condition |",
        "|------------|----------|------------|-----------------|"
    ]
    
    transitions = sorted(TransitionRules.VALID_TRANSITIONS)
    for from_state, to_state, event_type in transitions:
        guard = TransitionRules.get_guard_condition(from_state, to_state, event_type)
        guard_str = guard if guard else "-"
        lines.append(
            f"| {from_state.name} | {to_state.name} | {event_type} | {guard_str} |"
        )
    
    return "\n".join(lines)


def save_visualization_files(output_dir: str = "docs/fsm"):
    """
    Save visualization files to disk.
    
    Args:
        output_dir: Directory to save files to
    """
    import os
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Save DOT graph
    dot_content = generate_dot_graph()
    with open(f"{output_dir}/fsm_graph.dot", "w") as f:
        f.write(dot_content)
    
    # Save state table
    state_table = generate_state_table()
    with open(f"{output_dir}/states_table.md", "w") as f:
        f.write("# FSM State Definitions\n\n")
        f.write(state_table)
    
    # Save transition table
    transition_table = generate_transition_table()
    with open(f"{output_dir}/transitions_table.md", "w") as f:
        f.write("# FSM Transition Rules\n\n")
        f.write(transition_table)
    
    print(f"Visualization files saved to {output_dir}/")


if __name__ == "__main__":
    # Generate and print visualizations
    print("=== FSM Graph (DOT format) ===")
    print(generate_dot_graph())
    print("\n\n=== State Table ===")
    print(generate_state_table())
    print("\n\n=== Transition Table ===")
    print(generate_transition_table())
    
    # Save to files
    save_visualization_files()

