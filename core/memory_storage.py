"""
In-memory storage for stateless, per-request log analysis.

Designed for:
- Concurrent multi-user access (no locks)
- OCP/Kubernetes deployment (no persistent storage needed)
- Per-query analysis (no state accumulation)
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import uuid
import threading
from collections import OrderedDict


@dataclass
class DeviceSummary:
    """Summary of a device's changes."""
    hostname: str
    total_commands: int
    commands_with_changes: int
    commands_with_errors: int
    has_interface_changes: bool
    has_bgp_changes: bool
    has_ospf_changes: bool
    status: str  # "changed", "unchanged", "errors"


@dataclass
class CommandSummary:
    """Summary of a command's diff (memory-optimized, no raw output duplication)."""
    command: str
    has_changes: bool
    added_lines: int
    removed_lines: int
    diff_html: str = ""  # Only store the diff HTML, raw outputs fetched from device_diffs on demand


@dataclass
class AnalysisSession:
    """
    In-memory storage for a single analysis session.
    Each user/request gets their own session - no conflicts.
    """
    session_id: str
    change_number: str
    created_at: datetime
    devices: Dict[str, DeviceSummary] = field(default_factory=dict)
    commands: Dict[str, List[CommandSummary]] = field(default_factory=dict)  # hostname -> commands
    device_diffs: List[Any] = field(default_factory=list)  # Original DeviceDiff objects
    device_logs: Dict[str, Any] = field(default_factory=dict)  # Original parsed logs
    
    def get_statistics(self) -> Dict:
        """Get analysis statistics."""
        total_devices = len(self.devices)
        changed_devices = sum(1 for d in self.devices.values() if d.commands_with_changes > 0)
        error_devices = sum(1 for d in self.devices.values() if d.commands_with_errors > 0)
        interface_changes = sum(1 for d in self.devices.values() if d.has_interface_changes)
        bgp_changes = sum(1 for d in self.devices.values() if d.has_bgp_changes)
        ospf_changes = sum(1 for d in self.devices.values() if d.has_ospf_changes)
        total_commands = sum(d.total_commands for d in self.devices.values())
        commands_with_changes = sum(d.commands_with_changes for d in self.devices.values())
        
        return {
            "total_devices": total_devices,
            "changed_devices": changed_devices,
            "error_devices": error_devices,
            "interface_changes": interface_changes,
            "bgp_changes": bgp_changes,
            "ospf_changes": ospf_changes,
            "total_commands": total_commands,
            "commands_with_changes": commands_with_changes
        }
    
    def get_devices_paginated(self, page: int = 1, page_size: int = 50, 
                               status: Optional[str] = None) -> tuple:
        """Get paginated list of devices."""
        devices = list(self.devices.values())
        
        # Filter by status
        if status:
            if status == "changed":
                devices = [d for d in devices if d.commands_with_changes > 0]
            elif status == "unchanged":
                devices = [d for d in devices if d.commands_with_changes == 0]
            elif status == "errors":
                devices = [d for d in devices if d.commands_with_errors > 0]
        
        total = len(devices)
        start = (page - 1) * page_size
        end = start + page_size
        
        return devices[start:end], total
    
    def get_device_commands(self, hostname: str, changed_only: bool = False) -> List[CommandSummary]:
        """Get commands for a specific device."""
        commands = self.commands.get(hostname, [])
        if changed_only:
            commands = [c for c in commands if c.has_changes]
        return commands
    
    def get_command_diff(self, hostname: str, command: str) -> Optional[Dict]:
        """Get diff details for a specific command (fetches raw output from device_diffs)."""
        commands = self.commands.get(hostname, [])
        for cmd in commands:
            if cmd.command == command:
                # Fetch raw outputs from device_diffs (not duplicated in CommandSummary)
                pre_output = ""
                post_output = ""
                for device_diff in self.device_diffs:
                    if device_diff.hostname == hostname:
                        for cmd_diff in device_diff.command_diffs:
                            if cmd_diff.command == command:
                                pre_output = cmd_diff.pre_output
                                post_output = cmd_diff.post_output
                                break
                        break
                
                return {
                    "command": cmd.command,
                    "has_changes": cmd.has_changes,
                    "added_lines": cmd.added_lines,
                    "removed_lines": cmd.removed_lines,
                    "pre_output": pre_output,
                    "post_output": post_output,
                    "diff_html": cmd.diff_html
                }
        return None
    
    def search_devices(self, query: str) -> List[str]:
        """Search devices by hostname."""
        query_lower = query.lower()
        return [h for h in self.devices.keys() if query_lower in h.lower()]


class SessionManager:
    """
    Manages analysis sessions with automatic cleanup.
    
    Features:
    - Thread-safe session management
    - Automatic expiration of old sessions
    - Memory-efficient with LRU-style cleanup
    """
    
    MAX_SESSIONS = 100  # Max concurrent sessions before cleanup
    SESSION_TTL_MINUTES = 30  # Session lifetime
    
    def __init__(self):
        self._sessions: OrderedDict[str, AnalysisSession] = OrderedDict()
        self._lock = threading.Lock()
    
    def create_session(self, change_number: str) -> AnalysisSession:
        """Create a new analysis session."""
        session_id = str(uuid.uuid4())
        session = AnalysisSession(
            session_id=session_id,
            change_number=change_number,
            created_at=datetime.now()
        )
        
        with self._lock:
            # Cleanup old sessions if needed
            self._cleanup_old_sessions()
            self._sessions[session_id] = session
        
        return session
    
    def get_session(self, session_id: str) -> Optional[AnalysisSession]:
        """Get an existing session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                # Move to end (most recently used)
                self._sessions.move_to_end(session_id)
            return session
    
    def get_session_by_change(self, change_number: str) -> Optional[AnalysisSession]:
        """Get the most recent session for a change number."""
        with self._lock:
            for session in reversed(self._sessions.values()):
                if session.change_number == change_number:
                    return session
        return None
    
    def delete_session(self, session_id: str):
        """Delete a session."""
        with self._lock:
            self._sessions.pop(session_id, None)
    
    def remove_session(self, session_id: str) -> bool:
        """Remove a session and return True if it existed."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False
    
    def _cleanup_old_sessions(self):
        """Remove expired and excess sessions."""
        now = datetime.now()
        
        # Remove expired sessions
        expired = []
        for sid, session in self._sessions.items():
            age_minutes = (now - session.created_at).total_seconds() / 60
            if age_minutes > self.SESSION_TTL_MINUTES:
                expired.append(sid)
        
        for sid in expired:
            del self._sessions[sid]
        
        # Remove oldest sessions if over limit
        while len(self._sessions) > self.MAX_SESSIONS:
            self._sessions.popitem(last=False)
    
    def list_sessions(self) -> List[Dict]:
        """List all active sessions (for debugging)."""
        with self._lock:
            return [
                {
                    "session_id": s.session_id,
                    "change_number": s.change_number,
                    "created_at": s.created_at.isoformat(),
                    "device_count": len(s.devices)
                }
                for s in self._sessions.values()
            ]


def populate_session(session: AnalysisSession, device_logs: Dict, device_diffs: List) -> None:
    """
    Populate a session with analysis results.
    
    Args:
        session: The session to populate
        device_logs: Dict mapping hostname to (pre_log, post_log)
        device_diffs: List of DeviceDiff objects
    """
    session.device_logs = device_logs
    session.device_diffs = device_diffs
    
    for device_diff in device_diffs:
        hostname = device_diff.hostname
        
        # Analyze device for special changes
        has_interface_changes = False
        has_bgp_changes = False
        has_ospf_changes = False
        commands_with_errors = 0
        
        command_summaries = []
        
        for cmd_diff in device_diff.command_diffs:
            cmd_lower = cmd_diff.command.lower()
            
            if 'interface' in cmd_lower or 'ip int' in cmd_lower:
                if cmd_diff.has_changes:
                    has_interface_changes = True
            elif 'bgp' in cmd_lower:
                if cmd_diff.has_changes:
                    has_bgp_changes = True
            elif 'ospf' in cmd_lower:
                if cmd_diff.has_changes:
                    has_ospf_changes = True
            
            # Check for actual errors (not normal states)
            if cmd_diff.post_output:
                output_lower = cmd_diff.post_output.lower()
                if any(err in output_lower for err in ['error:', 'failed', 'failure', '%error']):
                    commands_with_errors += 1
            
            command_summaries.append(CommandSummary(
                command=cmd_diff.command,
                has_changes=cmd_diff.has_changes,
                added_lines=cmd_diff.added_lines,
                removed_lines=cmd_diff.removed_lines,
                diff_html=cmd_diff.diff_html
                # Note: pre_output/post_output NOT stored here - fetched from device_diffs on demand
            ))
        
        # Determine status
        status = "unchanged"
        if device_diff.commands_with_changes > 0:
            status = "changed"
        elif commands_with_errors > 0:
            status = "errors"
        
        session.devices[hostname] = DeviceSummary(
            hostname=hostname,
            total_commands=device_diff.total_commands,
            commands_with_changes=device_diff.commands_with_changes,
            commands_with_errors=commands_with_errors,
            has_interface_changes=has_interface_changes,
            has_bgp_changes=has_bgp_changes,
            has_ospf_changes=has_ospf_changes,
            status=status
        )
        
        session.commands[hostname] = command_summaries


# Global session manager (singleton)
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get the global session manager."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
