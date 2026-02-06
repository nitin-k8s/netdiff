"""
HTML diff generator for network device logs.

Generates side-by-side HTML diff reports with syntax highlighting.
"""
import difflib
from pathlib import Path
from typing import List, Optional, Dict
from dataclasses import dataclass
from jinja2 import Template

from core.parser import DeviceLog, CommandOutput
from core.masker import DataMasker, MASKING_PROFILES


@dataclass
class CommandDiff:
    """Represents the diff for a single command."""
    command: str
    has_changes: bool
    pre_output: str
    post_output: str
    diff_html: str
    added_lines: int
    removed_lines: int
    changed_lines: int


@dataclass
class DeviceDiff:
    """Represents the complete diff for a device."""
    hostname: str
    change_number: str
    command_diffs: List[CommandDiff]
    total_commands: int
    commands_with_changes: int
    total_added: int
    total_removed: int
    total_changed: int


class DiffGenerator:
    """Generates HTML diffs between pre and post logs."""
    
    def __init__(self, masker: Optional[DataMasker] = None, 
                 masking_categories: Optional[List[str]] = None):
        """
        Initialize diff generator.
        
        Args:
            masker: Optional DataMasker instance
            masking_categories: Categories to apply during masking
        """
        self.masker = masker or DataMasker()
        self.masking_categories = masking_categories
    
    def generate_command_diff(self, command: str, pre_output: str, 
                             post_output: str) -> CommandDiff:
        """
        Generate diff for a single command.
        
        Args:
            command: Command name
            pre_output: Pre-change output
            post_output: Post-change output
            
        Returns:
            CommandDiff object
        """
        # Apply masking
        _, masked_pre = self.masker.mask_command_output(command, pre_output, 
                                                         self.masking_categories)
        _, masked_post = self.masker.mask_command_output(command, post_output,
                                                          self.masking_categories)
        
        # Split into lines
        pre_lines = masked_pre.splitlines(keepends=True)
        post_lines = masked_post.splitlines(keepends=True)
        
        # Handle empty outputs - ensure at least empty line for comparison
        if not pre_lines:
            pre_lines = ['']
        if not post_lines:
            post_lines = ['']
        
        # Generate diff - use context=False to show ALL lines including additions
        # This ensures small outputs (like filtered logging) are always visible
        differ = difflib.HtmlDiff(wrapcolumn=80)
        diff_html = differ.make_table(
            pre_lines, 
            post_lines,
            fromdesc="Pre-Change",
            todesc="Post-Change",
            context=False  # Show full output, not just context around changes
        )
        
        # Count changes
        added = removed = 0
        for line in difflib.unified_diff(pre_lines, post_lines, lineterm=''):
            if line.startswith('+') and not line.startswith('+++'):
                added += 1
            elif line.startswith('-') and not line.startswith('---'):
                removed += 1
        
        has_changes = added > 0 or removed > 0
        # changed_lines represents lines that were modified (approximated as min of add/remove)
        # but we keep added_lines and removed_lines as the RAW counts for display
        changed = min(added, removed)
        
        return CommandDiff(
            command=command,
            has_changes=has_changes,
            pre_output=masked_pre,
            post_output=masked_post,
            diff_html=diff_html,
            added_lines=added,      # RAW count of + lines
            removed_lines=removed,  # RAW count of - lines
            changed_lines=changed   # Approximate modified lines
        )
    
    def generate_device_diff(self, pre_log: DeviceLog, 
                            post_log: DeviceLog) -> DeviceDiff:
        """
        Generate complete diff for a device.
        
        Args:
            pre_log: Pre-change device log
            post_log: Post-change device log
            
        Returns:
            DeviceDiff object
        """
        command_diffs = []
        
        # Get all unique commands
        pre_commands = {cmd.command: cmd for cmd in pre_log.commands}
        post_commands = {cmd.command: cmd for cmd in post_log.commands}
        
        all_commands = sorted(set(pre_commands.keys()) | set(post_commands.keys()))
        
        total_added = total_removed = total_changed = 0
        commands_with_changes = 0
        
        for command in all_commands:
            pre_output = pre_commands[command].output if command in pre_commands else ""
            post_output = post_commands[command].output if command in post_commands else ""
            
            cmd_diff = self.generate_command_diff(command, pre_output, post_output)
            command_diffs.append(cmd_diff)
            
            if cmd_diff.has_changes:
                commands_with_changes += 1
                total_added += cmd_diff.added_lines
                total_removed += cmd_diff.removed_lines
                total_changed += cmd_diff.changed_lines
        
        return DeviceDiff(
            hostname=pre_log.hostname,
            change_number=pre_log.change_number,
            command_diffs=command_diffs,
            total_commands=len(all_commands),
            commands_with_changes=commands_with_changes,
            total_added=total_added,
            total_removed=total_removed,
            total_changed=total_changed
        )
    
    def generate_html_report(self, device_diffs: List[DeviceDiff], 
                            output_path: Path,
                            include_unchanged: bool = False) -> Path:
        """
        Generate complete HTML report for all devices.
        
        Args:
            device_diffs: List of DeviceDiff objects
            output_path: Path to save HTML report
            include_unchanged: Include commands with no changes
            
        Returns:
            Path to generated HTML file
        """
        # Filter commands if needed
        if not include_unchanged:
            for device_diff in device_diffs:
                device_diff.command_diffs = [
                    cmd_diff for cmd_diff in device_diff.command_diffs 
                    if cmd_diff.has_changes
                ]
        
        # Render HTML
        html_content = self._render_html_template(device_diffs)
        
        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _render_html_template(self, device_diffs: List[DeviceDiff]) -> str:
        """Render HTML template with device diffs."""
        
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Device Change Report - {{ device_diffs[0].change_number }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; margin-bottom: 10px; }
        .header .summary { font-size: 14px; opacity: 0.9; }
        .container { max-width: 1400px; margin: 20px auto; padding: 0 20px; }
        .device-section { background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .device-header { background: #34495e; color: white; padding: 15px 20px; border-radius: 8px 8px 0 0; cursor: pointer; }
        .device-header:hover { background: #3d566e; }
        .device-header h2 { font-size: 18px; display: inline-block; }
        .device-stats { float: right; font-size: 14px; }
        .device-stats span { margin-left: 15px; padding: 4px 8px; background: rgba(255,255,255,0.2); border-radius: 3px; }
        .device-content { padding: 20px; }
        .command-section { margin-bottom: 30px; border-left: 3px solid #3498db; padding-left: 15px; }
        .command-title { font-size: 16px; font-weight: bold; color: #2c3e50; margin-bottom: 10px; font-family: 'Courier New', monospace; }
        .command-stats { font-size: 13px; color: #7f8c8d; margin-bottom: 10px; }
        .added { color: #27ae60; }
        .removed { color: #e74c3c; }
        .changed { color: #f39c12; }
        table.diff { font-family: 'Courier New', monospace; font-size: 12px; border-collapse: collapse; width: 100%; }
        table.diff td { padding: 2px 5px; vertical-align: top; white-space: pre-wrap; word-wrap: break-word; }
        table.diff .diff_header { background-color: #e0e0e0; font-weight: bold; }
        table.diff .diff_next { background-color: #c0c0c0; }
        table.diff .diff_add { background-color: #d4edda; }
        table.diff .diff_chg { background-color: #fff3cd; }
        table.diff .diff_sub { background-color: #f8d7da; }
        .collapsible { display: none; }
        .toggle-btn { background: #3498db; color: white; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; margin-top: 10px; font-size: 13px; }
        .toggle-btn:hover { background: #2980b9; }
        .no-changes { text-align: center; padding: 40px; color: #95a5a6; font-style: italic; }
    </style>
    <script>
        function toggleDevice(id) {
            const content = document.getElementById('device-' + id);
            content.style.display = content.style.display === 'none' ? 'block' : 'none';
        }
        function toggleAll() {
            const devices = document.querySelectorAll('.device-content');
            const allVisible = Array.from(devices).every(d => d.style.display !== 'none');
            devices.forEach(d => d.style.display = allVisible ? 'none' : 'block');
        }
    </script>
</head>
<body>
    <div class="header">
        <h1>Network Device Change Report</h1>
        <div class="summary">
            Change Number: {{ device_diffs[0].change_number }} | 
            Total Devices: {{ device_diffs|length }} | 
            Devices with Changes: {{ device_diffs|selectattr('commands_with_changes', 'gt', 0)|list|length }}
        </div>
    </div>
    
    <div class="container">
        <button class="toggle-btn" onclick="toggleAll()">Toggle All Devices</button>
        
        {% for device in device_diffs %}
        <div class="device-section">
            <div class="device-header" onclick="toggleDevice({{ loop.index }})">
                <h2>📡 {{ device.hostname }}</h2>
                <div class="device-stats">
                    <span>{{ device.commands_with_changes }}/{{ device.total_commands }} commands changed</span>
                    <span class="added">+{{ device.total_added }}</span>
                    <span class="removed">-{{ device.total_removed }}</span>
                    <span class="changed">~{{ device.total_changed }}</span>
                </div>
            </div>
            <div id="device-{{ loop.index }}" class="device-content">
                {% if device.command_diffs %}
                    {% for cmd_diff in device.command_diffs %}
                    <div class="command-section">
                        <div class="command-title">$ {{ cmd_diff.command }}</div>
                        <div class="command-stats">
                            <span class="added">+{{ cmd_diff.added_lines }} added</span> | 
                            <span class="removed">-{{ cmd_diff.removed_lines }} removed</span> | 
                            <span class="changed">~{{ cmd_diff.changed_lines }} changed</span>
                        </div>
                        {{ cmd_diff.diff_html|safe }}
                    </div>
                    {% endfor %}
                {% else %}
                    <div class="no-changes">No changes detected</div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
    </div>
</body>
</html>
        """
        
        template = Template(template_str)
        return template.render(device_diffs=device_diffs)
