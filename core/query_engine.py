"""
Smart query engine for network device logs.

Provides intelligent querying using pattern matching
and diff analysis on structured network output.
"""
import re
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from core.parser import DeviceLog, CommandOutput, LogType
from core.differ import DeviceDiff, CommandDiff


class QueryType(Enum):
    """Types of queries supported."""
    INTERFACE_STATUS = "interface_status"
    INTERFACE_DOWN = "interface_down"
    INTERFACE_UP = "interface_up"
    ERRORS = "errors"
    BGP_CHANGES = "bgp_changes"
    OSPF_CHANGES = "ospf_changes"
    ROUTING_CHANGES = "routing_changes"
    CONFIG_CHANGES = "config_changes"
    VLAN_CHANGES = "vlan_changes"
    GENERAL_DIFF = "general_diff"
    SEARCH = "search"


@dataclass
class QueryResult:
    """Result from a query."""
    query_type: QueryType
    summary: str
    devices_affected: List[str]
    details: List[Dict[str, Any]]
    total_findings: int


class LogQueryEngine:
    """
    Rule-based query engine for network device logs.
    Uses pattern matching and diff analysis.
    """
    
    # Patterns for interface status
    INTERFACE_STATUS_PATTERNS = [
        # Cisco IOS/IOS-XE show ip interface brief
        re.compile(r'^(\S+)\s+(\S+)\s+\S+\s+\S+\s+(up|down|administratively down)\s+(up|down)', re.MULTILINE | re.IGNORECASE),
        # Cisco show interfaces status (switches)
        re.compile(r'^(Gi\S+|Fa\S+|Te\S+|Eth\S+)\s+\S*\s+(connected|notconnect|disabled|err-disabled)\s+', re.MULTILINE | re.IGNORECASE),
        # Generic interface line protocol
        re.compile(r'^(\S+)\s+is\s+(up|down|administratively down),\s+line protocol is\s+(up|down)', re.MULTILINE | re.IGNORECASE),
    ]
    
    # Patterns for errors
    ERROR_PATTERNS = [
        re.compile(r'error|err-disable|fail|down|warning|critical', re.IGNORECASE),
        re.compile(r'%\w+-\d+-\w+:', re.IGNORECASE),  # Cisco syslog format
    ]
    
    # Patterns for BGP
    BGP_NEIGHBOR_PATTERN = re.compile(
        r'^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)',
        re.MULTILINE
    )
    
    # Patterns for OSPF
    OSPF_NEIGHBOR_PATTERN = re.compile(
        r'^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(FULL|2WAY|INIT|DOWN)/\S+\s+\S+\s+(\S+)\s+(\S+)',
        re.MULTILINE
    )
    
    def __init__(self, device_logs: Dict[str, Tuple[DeviceLog, DeviceLog]], 
                 device_diffs: List[DeviceDiff]):
        """
        Initialize query engine.
        
        Args:
            device_logs: Dict mapping hostname to (pre_log, post_log) tuple
            device_diffs: List of computed device diffs
        """
        self.device_logs = device_logs
        self.device_diffs = {d.hostname: d for d in device_diffs}
    
    def query(self, question: str) -> QueryResult:
        """
        Process a natural language question and return results.
        
        Args:
            question: User's question in natural language
            
        Returns:
            QueryResult with findings
        """
        question_lower = question.lower()
        
        # Detect query type from keywords
        if any(kw in question_lower for kw in ['interface', 'port', 'status']):
            if any(kw in question_lower for kw in ['down', 'went down', 'failed']):
                return self.find_interfaces_down()
            elif any(kw in question_lower for kw in ['up', 'came up', 'enabled']):
                return self.find_interfaces_up()
            else:
                return self.find_interface_changes()
        
        elif any(kw in question_lower for kw in ['bgp', 'neighbor', 'peer']):
            return self.find_bgp_changes()
        
        elif any(kw in question_lower for kw in ['ospf', 'routing protocol']):
            return self.find_ospf_changes()
        
        elif any(kw in question_lower for kw in ['route', 'routing']):
            return self.find_routing_changes()
        
        elif any(kw in question_lower for kw in ['error', 'fail', 'problem', 'issue']):
            return self.find_errors()
        
        elif any(kw in question_lower for kw in ['vlan', 'switch']):
            return self.find_vlan_changes()
        
        elif any(kw in question_lower for kw in ['config', 'configuration', 'running']):
            return self.find_config_changes()
        
        elif any(kw in question_lower for kw in ['change', 'differ', 'impact', 'affect']):
            return self.get_change_summary()
        
        else:
            # Try to extract search terms
            return self.search_logs(question)
    
    def find_interface_changes(self) -> QueryResult:
        """Find all interface status changes across devices."""
        details = []
        affected_devices = []
        
        for hostname, (pre_log, post_log) in self.device_logs.items():
            if not pre_log or not post_log:
                continue
            
            pre_interfaces = self._extract_interface_status(pre_log)
            post_interfaces = self._extract_interface_status(post_log)
            
            changes = []
            all_interfaces = set(pre_interfaces.keys()) | set(post_interfaces.keys())
            
            for iface in all_interfaces:
                pre_status = pre_interfaces.get(iface, "not present")
                post_status = post_interfaces.get(iface, "not present")
                
                if pre_status != post_status:
                    changes.append({
                        "interface": iface,
                        "pre_status": pre_status,
                        "post_status": post_status,
                        "change_type": self._classify_change(pre_status, post_status)
                    })
            
            if changes:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "changes": changes,
                    "total_changes": len(changes)
                })
        
        total = sum(d["total_changes"] for d in details)
        
        if not details:
            summary = "No interface status changes detected across any devices."
        else:
            summary = f"Found {total} interface status change(s) across {len(affected_devices)} device(s):\n"
            for d in details:
                summary += f"\n**{d['hostname']}**: {d['total_changes']} change(s)\n"
                for c in d['changes'][:5]:  # Limit to 5 per device in summary
                    summary += f"  • {c['interface']}: {c['pre_status']} → {c['post_status']}\n"
                if d['total_changes'] > 5:
                    summary += f"  ... and {d['total_changes'] - 5} more\n"
        
        return QueryResult(
            query_type=QueryType.INTERFACE_STATUS,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    def find_interfaces_down(self) -> QueryResult:
        """Find interfaces that went down during the change."""
        details = []
        affected_devices = []
        
        for hostname, (pre_log, post_log) in self.device_logs.items():
            if not pre_log or not post_log:
                continue
            
            pre_interfaces = self._extract_interface_status(pre_log)
            post_interfaces = self._extract_interface_status(post_log)
            
            down_interfaces = []
            for iface, post_status in post_interfaces.items():
                pre_status = pre_interfaces.get(iface, "not present")
                
                if self._is_down(post_status) and not self._is_down(pre_status):
                    down_interfaces.append({
                        "interface": iface,
                        "pre_status": pre_status,
                        "post_status": post_status
                    })
            
            if down_interfaces:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "interfaces": down_interfaces
                })
        
        total = sum(len(d["interfaces"]) for d in details)
        
        if not details:
            summary = "✅ No interfaces went down during the change."
        else:
            summary = f"⚠️ {total} interface(s) went DOWN across {len(affected_devices)} device(s):\n"
            for d in details:
                summary += f"\n**{d['hostname']}**:\n"
                for iface in d['interfaces']:
                    summary += f"  • {iface['interface']}: {iface['pre_status']} → {iface['post_status']}\n"
        
        return QueryResult(
            query_type=QueryType.INTERFACE_DOWN,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    def find_interfaces_up(self) -> QueryResult:
        """Find interfaces that came up during the change."""
        details = []
        affected_devices = []
        
        for hostname, (pre_log, post_log) in self.device_logs.items():
            if not pre_log or not post_log:
                continue
            
            pre_interfaces = self._extract_interface_status(pre_log)
            post_interfaces = self._extract_interface_status(post_log)
            
            up_interfaces = []
            for iface, post_status in post_interfaces.items():
                pre_status = pre_interfaces.get(iface, "not present")
                
                if self._is_up(post_status) and not self._is_up(pre_status):
                    up_interfaces.append({
                        "interface": iface,
                        "pre_status": pre_status,
                        "post_status": post_status
                    })
            
            if up_interfaces:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "interfaces": up_interfaces
                })
        
        total = sum(len(d["interfaces"]) for d in details)
        
        if not details:
            summary = "No interfaces came up during the change."
        else:
            summary = f"✅ {total} interface(s) came UP across {len(affected_devices)} device(s):\n"
            for d in details:
                summary += f"\n**{d['hostname']}**:\n"
                for iface in d['interfaces']:
                    summary += f"  • {iface['interface']}: {iface['pre_status']} → {iface['post_status']}\n"
        
        return QueryResult(
            query_type=QueryType.INTERFACE_UP,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    def find_errors(self) -> QueryResult:
        """Find errors in post-change logs."""
        details = []
        affected_devices = []
        
        for hostname, (pre_log, post_log) in self.device_logs.items():
            if not post_log:
                continue
            
            errors = []
            for cmd in post_log.commands:
                for pattern in self.ERROR_PATTERNS:
                    matches = pattern.findall(cmd.output)
                    if matches:
                        # Get context lines with errors
                        for line in cmd.output.split('\n'):
                            if pattern.search(line):
                                errors.append({
                                    "command": cmd.command,
                                    "error_line": line.strip()
                                })
            
            # Filter out common false positives
            errors = [e for e in errors if not self._is_false_positive_error(e['error_line'])]
            
            if errors:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "errors": errors[:10]  # Limit to 10
                })
        
        total = sum(len(d["errors"]) for d in details)
        
        if not details:
            summary = "✅ No errors found in post-change logs."
        else:
            summary = f"⚠️ Found {total} error indication(s) across {len(affected_devices)} device(s):\n"
            for d in details:
                summary += f"\n**{d['hostname']}**:\n"
                for err in d['errors'][:5]:
                    summary += f"  • [{err['command']}] {err['error_line'][:80]}\n"
        
        return QueryResult(
            query_type=QueryType.ERRORS,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    def find_bgp_changes(self) -> QueryResult:
        """Find BGP neighbor changes."""
        details = []
        affected_devices = []
        
        for hostname, (pre_log, post_log) in self.device_logs.items():
            if not pre_log or not post_log:
                continue
            
            pre_neighbors = self._extract_bgp_neighbors(pre_log)
            post_neighbors = self._extract_bgp_neighbors(post_log)
            
            changes = []
            
            # Check for new neighbors
            for neighbor, data in post_neighbors.items():
                if neighbor not in pre_neighbors:
                    changes.append({
                        "neighbor": neighbor,
                        "change": "NEW",
                        "as": data.get("as", "?"),
                        "state": data.get("state", "?")
                    })
                elif pre_neighbors[neighbor].get("state") != data.get("state"):
                    changes.append({
                        "neighbor": neighbor,
                        "change": "STATE_CHANGE",
                        "pre_state": pre_neighbors[neighbor].get("state"),
                        "post_state": data.get("state")
                    })
            
            # Check for removed neighbors
            for neighbor in pre_neighbors:
                if neighbor not in post_neighbors:
                    changes.append({
                        "neighbor": neighbor,
                        "change": "REMOVED",
                        "as": pre_neighbors[neighbor].get("as", "?")
                    })
            
            if changes:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "changes": changes
                })
        
        total = sum(len(d["changes"]) for d in details)
        
        if not details:
            summary = "No BGP neighbor changes detected."
        else:
            summary = f"Found {total} BGP change(s) across {len(affected_devices)} device(s):\n"
            for d in details:
                summary += f"\n**{d['hostname']}**:\n"
                for c in d['changes']:
                    if c['change'] == 'NEW':
                        summary += f"  • NEW neighbor {c['neighbor']} (AS {c['as']}) - {c['state']}\n"
                    elif c['change'] == 'REMOVED':
                        summary += f"  • REMOVED neighbor {c['neighbor']} (AS {c['as']})\n"
                    else:
                        summary += f"  • {c['neighbor']}: {c['pre_state']} → {c['post_state']}\n"
        
        return QueryResult(
            query_type=QueryType.BGP_CHANGES,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    def find_ospf_changes(self) -> QueryResult:
        """Find OSPF neighbor changes."""
        details = []
        affected_devices = []
        
        for hostname, (pre_log, post_log) in self.device_logs.items():
            if not pre_log or not post_log:
                continue
            
            pre_neighbors = self._extract_ospf_neighbors(pre_log)
            post_neighbors = self._extract_ospf_neighbors(post_log)
            
            changes = []
            
            for neighbor, data in post_neighbors.items():
                if neighbor not in pre_neighbors:
                    changes.append({
                        "neighbor": neighbor,
                        "change": "NEW",
                        "state": data.get("state", "?"),
                        "interface": data.get("interface", "?")
                    })
                elif pre_neighbors[neighbor].get("state") != data.get("state"):
                    changes.append({
                        "neighbor": neighbor,
                        "change": "STATE_CHANGE",
                        "pre_state": pre_neighbors[neighbor].get("state"),
                        "post_state": data.get("state")
                    })
            
            for neighbor in pre_neighbors:
                if neighbor not in post_neighbors:
                    changes.append({
                        "neighbor": neighbor,
                        "change": "REMOVED"
                    })
            
            if changes:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "changes": changes
                })
        
        total = sum(len(d["changes"]) for d in details)
        
        if not details:
            summary = "No OSPF neighbor changes detected."
        else:
            summary = f"Found {total} OSPF change(s) across {len(affected_devices)} device(s):\n"
            for d in details:
                summary += f"\n**{d['hostname']}**:\n"
                for c in d['changes']:
                    if c['change'] == 'NEW':
                        summary += f"  • NEW neighbor {c['neighbor']} ({c['state']}) on {c['interface']}\n"
                    elif c['change'] == 'REMOVED':
                        summary += f"  • REMOVED neighbor {c['neighbor']}\n"
                    else:
                        summary += f"  • {c['neighbor']}: {c['pre_state']} → {c['post_state']}\n"
        
        return QueryResult(
            query_type=QueryType.OSPF_CHANGES,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    def find_vlan_changes(self) -> QueryResult:
        """Find VLAN changes."""
        details = []
        affected_devices = []
        
        for hostname, (pre_log, post_log) in self.device_logs.items():
            if not pre_log or not post_log:
                continue
            
            pre_vlans = self._extract_vlans(pre_log)
            post_vlans = self._extract_vlans(post_log)
            
            changes = []
            
            for vlan_id, data in post_vlans.items():
                if vlan_id not in pre_vlans:
                    changes.append({
                        "vlan": vlan_id,
                        "change": "NEW",
                        "name": data.get("name", "")
                    })
            
            for vlan_id in pre_vlans:
                if vlan_id not in post_vlans:
                    changes.append({
                        "vlan": vlan_id,
                        "change": "REMOVED",
                        "name": pre_vlans[vlan_id].get("name", "")
                    })
            
            if changes:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "changes": changes
                })
        
        total = sum(len(d["changes"]) for d in details)
        
        if not details:
            summary = "No VLAN changes detected."
        else:
            summary = f"Found {total} VLAN change(s) across {len(affected_devices)} device(s):\n"
            for d in details:
                summary += f"\n**{d['hostname']}**:\n"
                for c in d['changes']:
                    if c['change'] == 'NEW':
                        summary += f"  • NEW VLAN {c['vlan']} ({c['name']})\n"
                    else:
                        summary += f"  • REMOVED VLAN {c['vlan']} ({c['name']})\n"
        
        return QueryResult(
            query_type=QueryType.VLAN_CHANGES,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    def find_config_changes(self) -> QueryResult:
        """Find configuration changes."""
        details = []
        affected_devices = []
        
        for hostname, diff in self.device_diffs.items():
            config_changes = []
            
            for cmd_diff in diff.command_diffs:
                if 'running-config' in cmd_diff.command.lower() or 'config' in cmd_diff.command.lower():
                    if cmd_diff.has_changes:
                        config_changes.append({
                            "command": cmd_diff.command,
                            "added": cmd_diff.added_lines,
                            "removed": cmd_diff.removed_lines
                        })
            
            if config_changes:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "changes": config_changes
                })
        
        total = sum(len(d["changes"]) for d in details)
        
        if not details:
            summary = "No configuration changes detected."
        else:
            summary = f"Found configuration changes on {len(affected_devices)} device(s):\n"
            for d in details:
                summary += f"\n**{d['hostname']}**:\n"
                for c in d['changes']:
                    summary += f"  • {c['command']}: +{c['added']}/-{c['removed']} lines\n"
        
        return QueryResult(
            query_type=QueryType.CONFIG_CHANGES,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    def find_routing_changes(self) -> QueryResult:
        """Find routing table changes."""
        details = []
        affected_devices = []
        
        for hostname, diff in self.device_diffs.items():
            routing_changes = []
            
            for cmd_diff in diff.command_diffs:
                cmd_lower = cmd_diff.command.lower()
                if 'route' in cmd_lower or 'routing' in cmd_lower:
                    if cmd_diff.has_changes:
                        routing_changes.append({
                            "command": cmd_diff.command,
                            "added": cmd_diff.added_lines,
                            "removed": cmd_diff.removed_lines
                        })
            
            if routing_changes:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "changes": routing_changes
                })
        
        total = sum(len(d["changes"]) for d in details)
        
        if not details:
            summary = "No routing changes detected."
        else:
            summary = f"Found routing changes on {len(affected_devices)} device(s):\n"
            for d in details:
                summary += f"\n**{d['hostname']}**:\n"
                for c in d['changes']:
                    summary += f"  • {c['command']}: +{c['added']}/-{c['removed']} entries\n"
        
        return QueryResult(
            query_type=QueryType.ROUTING_CHANGES,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    def get_change_summary(self) -> QueryResult:
        """Get overall change summary."""
        details = []
        affected_devices = []
        
        for hostname, diff in self.device_diffs.items():
            if diff.commands_with_changes > 0:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "commands_changed": diff.commands_with_changes,
                    "total_commands": diff.total_commands,
                    "lines_added": diff.total_added,
                    "lines_removed": diff.total_removed
                })
        
        total = len(affected_devices)
        
        summary = f"**Change Summary** ({len(self.device_diffs)} devices analyzed):\n\n"
        
        if not affected_devices:
            summary += "✅ No changes detected on any device."
        else:
            summary += f"📊 {total} device(s) have changes:\n"
            for d in sorted(details, key=lambda x: x['commands_changed'], reverse=True):
                summary += f"\n**{d['hostname']}**:\n"
                summary += f"  • {d['commands_changed']}/{d['total_commands']} commands changed\n"
                summary += f"  • +{d['lines_added']} added, -{d['lines_removed']} removed\n"
        
        return QueryResult(
            query_type=QueryType.GENERAL_DIFF,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    def search_logs(self, search_term: str) -> QueryResult:
        """Search for a term in all logs."""
        details = []
        affected_devices = []
        
        # Clean up search term
        search_pattern = re.compile(re.escape(search_term.strip()), re.IGNORECASE)
        
        for hostname, (pre_log, post_log) in self.device_logs.items():
            matches = []
            
            for log, log_type in [(pre_log, "PRE"), (post_log, "POST")]:
                if not log:
                    continue
                
                for cmd in log.commands:
                    if search_pattern.search(cmd.output) or search_pattern.search(cmd.command):
                        # Find matching lines
                        for line in cmd.output.split('\n'):
                            if search_pattern.search(line):
                                matches.append({
                                    "log_type": log_type,
                                    "command": cmd.command,
                                    "line": line.strip()[:100]
                                })
            
            if matches:
                affected_devices.append(hostname)
                details.append({
                    "hostname": hostname,
                    "matches": matches[:20]  # Limit
                })
        
        total = sum(len(d["matches"]) for d in details)
        
        if not details:
            summary = f"No matches found for '{search_term}'."
        else:
            summary = f"Found {total} match(es) for '{search_term}' across {len(affected_devices)} device(s):\n"
            for d in details[:5]:
                summary += f"\n**{d['hostname']}** ({len(d['matches'])} matches):\n"
                for m in d['matches'][:3]:
                    summary += f"  • [{m['log_type']}] {m['command']}: {m['line'][:60]}...\n"
        
        return QueryResult(
            query_type=QueryType.SEARCH,
            summary=summary,
            devices_affected=affected_devices,
            details=details,
            total_findings=total
        )
    
    # Helper methods
    def _extract_interface_status(self, device_log: DeviceLog) -> Dict[str, str]:
        """Extract interface status from device log."""
        interfaces = {}
        
        for cmd in device_log.commands:
            # Try each pattern
            for pattern in self.INTERFACE_STATUS_PATTERNS:
                matches = pattern.findall(cmd.output)
                for match in matches:
                    if len(match) >= 2:
                        iface = match[0]
                        # Determine status based on pattern type
                        if len(match) == 4:  # show ip int brief style
                            status = f"{match[2]}/{match[3]}"
                        elif len(match) == 3:  # show interfaces style
                            status = f"{match[1]}/{match[2]}"
                        else:
                            status = match[1]
                        interfaces[iface] = status.lower()
        
        return interfaces
    
    def _extract_bgp_neighbors(self, device_log: DeviceLog) -> Dict[str, Dict]:
        """Extract BGP neighbors from device log."""
        neighbors = {}
        
        for cmd in device_log.commands:
            if 'bgp' in cmd.command.lower():
                matches = self.BGP_NEIGHBOR_PATTERN.findall(cmd.output)
                for match in matches:
                    neighbors[match[0]] = {
                        "as": match[1],
                        "state": match[3] if len(match) > 3 else "?"
                    }
        
        return neighbors
    
    def _extract_ospf_neighbors(self, device_log: DeviceLog) -> Dict[str, Dict]:
        """Extract OSPF neighbors from device log."""
        neighbors = {}
        
        for cmd in device_log.commands:
            if 'ospf' in cmd.command.lower():
                matches = self.OSPF_NEIGHBOR_PATTERN.findall(cmd.output)
                for match in matches:
                    neighbors[match[0]] = {
                        "state": match[1],
                        "interface": match[3] if len(match) > 3 else "?"
                    }
        
        return neighbors
    
    def _extract_vlans(self, device_log: DeviceLog) -> Dict[str, Dict]:
        """Extract VLANs from device log."""
        vlans = {}
        vlan_pattern = re.compile(r'^(\d+)\s+(\S+)\s+(active|suspend)', re.MULTILINE | re.IGNORECASE)
        
        for cmd in device_log.commands:
            if 'vlan' in cmd.command.lower():
                matches = vlan_pattern.findall(cmd.output)
                for match in matches:
                    vlans[match[0]] = {
                        "name": match[1],
                        "status": match[2]
                    }
        
        return vlans
    
    def _is_down(self, status: str) -> bool:
        """Check if status indicates down."""
        down_indicators = ['down', 'notconnect', 'disabled', 'err-disabled', 'not present']
        return any(ind in status.lower() for ind in down_indicators)
    
    def _is_up(self, status: str) -> bool:
        """Check if status indicates up."""
        up_indicators = ['up', 'connected']
        status_lower = status.lower()
        return any(ind in status_lower for ind in up_indicators) and 'down' not in status_lower
    
    def _classify_change(self, pre: str, post: str) -> str:
        """Classify the type of change."""
        if self._is_down(pre) and self._is_up(post):
            return "CAME_UP"
        elif self._is_up(pre) and self._is_down(post):
            return "WENT_DOWN"
        elif pre == "not present":
            return "NEW"
        elif post == "not present":
            return "REMOVED"
        else:
            return "MODIFIED"
    
    def _is_false_positive_error(self, line: str) -> bool:
        """Filter out common false positive error matches."""
        false_positives = [
            '0 input errors',
            '0 output errors',
            'no error',
            'error count: 0',
            'errors: 0'
        ]
        line_lower = line.lower()
        return any(fp in line_lower for fp in false_positives)
