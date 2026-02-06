"""
Log parser for network device command/output format.

Parses logs in the format:
command: <command>
<output>
command: <command>
<output>
"""
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class LogType(Enum):
    """Type of log file."""
    PRE = "pre"
    POST = "post"


@dataclass
class CommandOutput:
    """Represents a single command and its output."""
    command: str
    output: str
    line_start: int
    line_end: int
    
    def __str__(self) -> str:
        return f"Command: {self.command}\nLines: {self.line_start}-{self.line_end}"


@dataclass
class DeviceLog:
    """Represents logs for a single device."""
    hostname: str
    change_number: str
    log_type: LogType
    commands: List[CommandOutput]
    file_path: Path
    
    def get_command_by_name(self, command_name: str) -> Optional[CommandOutput]:
        """Find a command by its name."""
        for cmd in self.commands:
            if cmd.command.strip() == command_name.strip():
                return cmd
        return None
    
    def get_commands_matching(self, pattern: str) -> List[CommandOutput]:
        """Find commands matching a regex pattern."""
        regex = re.compile(pattern, re.IGNORECASE)
        return [cmd for cmd in self.commands if regex.search(cmd.command)]


class LogParser:
    """Parser for network device logs."""
    
    # Pattern to match command lines
    COMMAND_PATTERN = re.compile(r'^command:\s*(.+)$', re.IGNORECASE)
    
    # Glob patterns for pre/post logs (checked in order, first match wins)
    PRE_FILE_GLOBS = ['*pre*.log', '*pre*.txt']
    POST_FILE_GLOBS = ['*post*.log', '*post*.txt']
    
    def __init__(self):
        self.parsed_logs: Dict[str, Dict[str, DeviceLog]] = {}
    
    def _find_log_file(self, device_dir: Path, globs: List[str]) -> Optional[Path]:
        """Find first matching log file using glob patterns."""
        for pattern in globs:
            matches = list(device_dir.glob(pattern))
            if matches:
                # Return first match (sorted for consistency)
                return sorted(matches)[0]
        return None
    
    def parse_file(self, file_path: Path, hostname: str, change_number: str, 
                   log_type: LogType) -> DeviceLog:
        """
        Parse a single log file.
        
        Args:
            file_path: Path to the log file
            hostname: Device hostname
            change_number: Change number (e.g., CHG12345)
            log_type: Pre or post log
            
        Returns:
            DeviceLog object containing parsed commands
        """
        commands = []
        current_command = None
        current_output_lines = []
        line_start = 0
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines, start=1):
            # Check if this is a command line
            match = self.COMMAND_PATTERN.match(line.strip())
            
            if match:
                # Save previous command if exists
                if current_command is not None:
                    commands.append(CommandOutput(
                        command=current_command,
                        output=''.join(current_output_lines),
                        line_start=line_start,
                        line_end=line_num - 1
                    ))
                
                # Start new command
                current_command = match.group(1).strip()
                current_output_lines = []
                line_start = line_num
            else:
                # This is output for the current command
                if current_command is not None:
                    current_output_lines.append(line)
        
        # Don't forget the last command
        if current_command is not None:
            commands.append(CommandOutput(
                command=current_command,
                output=''.join(current_output_lines),
                line_start=line_start,
                line_end=len(lines)
            ))
        
        device_log = DeviceLog(
            hostname=hostname,
            change_number=change_number,
            log_type=log_type,
            commands=commands,
            file_path=file_path
        )
        
        # Cache the parsed log
        if change_number not in self.parsed_logs:
            self.parsed_logs[change_number] = {}
        
        key = f"{hostname}_{log_type.value}"
        self.parsed_logs[change_number][key] = device_log
        
        return device_log
    
    def parse_change_directory(self, change_dir: Path) -> Dict[str, Tuple[DeviceLog, DeviceLog]]:
        """
        Parse all devices in a directory.
        
        Expected structure - user provides path to folder containing device directories:
        <path>/
          <hostname>/
            *pre*.log or *pre*.txt
            *post*.log or *post*.txt
        
        Args:
            change_dir: Path to directory containing device folders
            
        Returns:
            Dictionary mapping hostname to (pre_log, post_log) tuple
        """
        change_number = change_dir.name
        
        if not change_dir.exists():
            raise ValueError(f"Directory not found: {change_dir}")
        
        if not change_dir.is_dir():
            raise ValueError(f"Path is not a directory: {change_dir}")
        
        device_logs = {}
        
        # Iterate through device directories
        for device_dir in change_dir.iterdir():
            if not device_dir.is_dir():
                continue
            
            hostname = device_dir.name
            
            # Find pre and post log files using glob patterns
            pre_log_path = self._find_log_file(device_dir, self.PRE_FILE_GLOBS)
            post_log_path = self._find_log_file(device_dir, self.POST_FILE_GLOBS)
            
            # Parse pre and post logs
            pre_log = None
            post_log = None
            
            if pre_log_path:
                pre_log = self.parse_file(pre_log_path, hostname, change_number, LogType.PRE)
            
            if post_log_path:
                post_log = self.parse_file(post_log_path, hostname, change_number, LogType.POST)
            
            if pre_log or post_log:
                device_logs[hostname] = (pre_log, post_log)
        
        return device_logs
    
    def get_all_command_names(self, change_number: str) -> List[str]:
        """Get all unique command names across all devices in a change."""
        if change_number not in self.parsed_logs:
            return []
        
        command_names = set()
        for device_log in self.parsed_logs[change_number].values():
            for cmd in device_log.commands:
                command_names.add(cmd.command)
        
        return sorted(list(command_names))
