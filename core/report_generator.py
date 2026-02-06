"""
Optimized diff generator for large-scale device logs.

Generates:
- Lightweight index pages
- On-demand per-device diffs
- Paginated HTML reports
"""
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
import html
import difflib
from jinja2 import Template

from .differ import DiffGenerator, DeviceDiff, CommandDiff
from .masker import DataMasker


# Templates for optimized reports
INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ change_number }} - Change Analysis</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
        }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .stat-number { font-size: 32px; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; font-size: 12px; text-transform: uppercase; }
        
        .filters {
            background: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }
        .filters input, .filters select {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .filters input[type="text"] { width: 250px; }
        
        .device-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
        }
        
        .device-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            text-decoration: none;
            color: inherit;
            display: block;
        }
        .device-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.15);
        }
        
        .device-name {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .status-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 500;
        }
        .status-changed { background: #fff3cd; color: #856404; }
        .status-unchanged { background: #d4edda; color: #155724; }
        .status-errors { background: #f8d7da; color: #721c24; }
        
        .device-stats {
            display: flex;
            gap: 15px;
            font-size: 13px;
            color: #666;
        }
        .device-stats span { display: flex; align-items: center; gap: 4px; }
        
        .change-indicators {
            margin-top: 10px;
            display: flex;
            gap: 8px;
        }
        .indicator {
            font-size: 11px;
            padding: 2px 6px;
            border-radius: 4px;
            background: #e9ecef;
        }
        .indicator.active { background: #667eea; color: white; }
        
        .pagination {
            margin-top: 20px;
            display: flex;
            justify-content: center;
            gap: 5px;
        }
        .pagination a, .pagination span {
            padding: 8px 12px;
            border-radius: 4px;
            text-decoration: none;
            color: #667eea;
            background: white;
        }
        .pagination a:hover { background: #667eea; color: white; }
        .pagination .current { background: #667eea; color: white; }
        
        .no-results {
            text-align: center;
            padding: 40px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 {{ change_number }}</h1>
            <p>Change Analysis Report - {{ total_devices }} devices analyzed</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{{ total_devices }}</div>
                <div class="stat-label">Total Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ changed_devices }}</div>
                <div class="stat-label">With Changes</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ error_devices }}</div>
                <div class="stat-label">With Errors</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ interface_changes }}</div>
                <div class="stat-label">Interface Changes</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ bgp_changes }}</div>
                <div class="stat-label">BGP Changes</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ ospf_changes }}</div>
                <div class="stat-label">OSPF Changes</div>
            </div>
        </div>
        
        <div class="filters">
            <input type="text" id="searchInput" placeholder="🔍 Search devices..." onkeyup="filterDevices()">
            <select id="statusFilter" onchange="filterDevices()">
                <option value="">All Status</option>
                <option value="changed">Changed</option>
                <option value="unchanged">Unchanged</option>
                <option value="errors">Errors</option>
            </select>
            <select id="sortBy" onchange="sortDevices()">
                <option value="name">Sort by Name</option>
                <option value="changes">Sort by Changes</option>
                <option value="status">Sort by Status</option>
            </select>
        </div>
        
        <div class="device-grid" id="deviceGrid">
            {% for device in devices %}
            <a href="devices/{{ device.hostname }}.html" class="device-card" 
               data-hostname="{{ device.hostname }}" 
               data-status="{{ device.status }}"
               data-changes="{{ device.commands_with_changes }}">
                <div class="device-name">
                    🖥️ {{ device.hostname }}
                    <span class="status-badge status-{{ device.status }}">{{ device.status }}</span>
                </div>
                <div class="device-stats">
                    <span>📝 {{ device.total_commands }} commands</span>
                    <span>✏️ {{ device.commands_with_changes }} changed</span>
                </div>
                <div class="change-indicators">
                    <span class="indicator {{ 'active' if device.has_interface_changes else '' }}">Interface</span>
                    <span class="indicator {{ 'active' if device.has_bgp_changes else '' }}">BGP</span>
                    <span class="indicator {{ 'active' if device.has_ospf_changes else '' }}">OSPF</span>
                </div>
            </a>
            {% endfor %}
        </div>
        
        {% if total_pages > 1 %}
        <div class="pagination">
            {% if current_page > 1 %}
            <a href="index_{{ current_page - 1 }}.html">← Prev</a>
            {% endif %}
            
            {% for p in range(1, total_pages + 1) %}
                {% if p == current_page %}
                <span class="current">{{ p }}</span>
                {% elif p <= 3 or p > total_pages - 3 or (p >= current_page - 2 and p <= current_page + 2) %}
                <a href="index{% if p > 1 %}_{{ p }}{% endif %}.html">{{ p }}</a>
                {% elif p == 4 or p == total_pages - 3 %}
                <span>...</span>
                {% endif %}
            {% endfor %}
            
            {% if current_page < total_pages %}
            <a href="index_{{ current_page + 1 }}.html">Next →</a>
            {% endif %}
        </div>
        {% endif %}
    </div>
    
    <script>
        function filterDevices() {
            const search = document.getElementById('searchInput').value.toLowerCase();
            const status = document.getElementById('statusFilter').value;
            const cards = document.querySelectorAll('.device-card');
            
            cards.forEach(card => {
                const hostname = card.dataset.hostname.toLowerCase();
                const cardStatus = card.dataset.status;
                
                const matchesSearch = hostname.includes(search);
                const matchesStatus = !status || cardStatus === status;
                
                card.style.display = matchesSearch && matchesStatus ? 'block' : 'none';
            });
        }
        
        function sortDevices() {
            const sortBy = document.getElementById('sortBy').value;
            const grid = document.getElementById('deviceGrid');
            const cards = Array.from(grid.querySelectorAll('.device-card'));
            
            cards.sort((a, b) => {
                if (sortBy === 'name') {
                    return a.dataset.hostname.localeCompare(b.dataset.hostname);
                } else if (sortBy === 'changes') {
                    return parseInt(b.dataset.changes) - parseInt(a.dataset.changes);
                } else if (sortBy === 'status') {
                    const order = {'errors': 0, 'changed': 1, 'unchanged': 2};
                    return order[a.dataset.status] - order[b.dataset.status];
                }
            });
            
            cards.forEach(card => grid.appendChild(card));
        }
    </script>
</body>
</html>
"""

DEVICE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ hostname }} - {{ change_number }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        
        .breadcrumb {
            margin-bottom: 20px;
            font-size: 14px;
        }
        .breadcrumb a { color: #667eea; text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
        
        .header {
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 24px; margin-bottom: 10px; }
        .header-stats {
            display: flex;
            gap: 20px;
            color: #666;
            font-size: 14px;
        }
        
        .filters {
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
        }
        .filter-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            background: #e9ecef;
            color: #333;
        }
        .filter-btn.active { background: #667eea; color: white; }
        
        .command-list { display: flex; flex-direction: column; gap: 10px; }
        
        .command-card {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .command-header {
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
        }
        .command-header:hover { background: #e9ecef; }
        
        .command-name {
            font-family: 'Consolas', monospace;
            font-size: 14px;
            font-weight: 600;
        }
        
        .command-meta {
            display: flex;
            gap: 15px;
            font-size: 12px;
            color: #666;
        }
        .added { color: #28a745; }
        .removed { color: #dc3545; }
        
        .command-diff {
            display: none;
            max-height: 500px;
            overflow-y: auto;
        }
        .command-diff.expanded { display: block; }
        
        .diff-table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'Consolas', monospace;
            font-size: 12px;
        }
        .diff-table td {
            padding: 2px 10px;
            white-space: pre-wrap;
            word-break: break-all;
            vertical-align: top;
        }
        .diff-table .line-num {
            width: 50px;
            text-align: right;
            color: #999;
            background: #f8f9fa;
            user-select: none;
        }
        .diff-table .line-add { background: #d4edda; }
        .diff-table .line-del { background: #f8d7da; }
        .diff-table .line-ctx { background: white; }
        
        .no-changes {
            padding: 20px;
            text-align: center;
            color: #666;
            font-style: italic;
        }
        
        .toggle-icon {
            transition: transform 0.2s;
        }
        .command-card.expanded .toggle-icon {
            transform: rotate(180deg);
        }
        
        .expand-all {
            margin-bottom: 15px;
        }
        .expand-all button {
            padding: 8px 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="breadcrumb">
            <a href="../index.html">{{ change_number }}</a> / <span>{{ hostname }}</span>
        </div>
        
        <div class="header">
            <h1>🖥️ {{ hostname }}</h1>
            <div class="header-stats">
                <span>📝 {{ total_commands }} commands</span>
                <span>✏️ {{ commands_with_changes }} with changes</span>
                <span class="status-{{ status }}">Status: {{ status }}</span>
            </div>
        </div>
        
        <div class="filters">
            <button class="filter-btn active" onclick="filterCommands('all')">All ({{ total_commands }})</button>
            <button class="filter-btn" onclick="filterCommands('changed')">Changed ({{ commands_with_changes }})</button>
            <button class="filter-btn" onclick="filterCommands('unchanged')">Unchanged ({{ total_commands - commands_with_changes }})</button>
        </div>
        
        <div class="expand-all">
            <button onclick="toggleAll()">Expand/Collapse All Changed</button>
        </div>
        
        <div class="command-list" id="commandList">
            {% for cmd in commands %}
            <div class="command-card" data-has-changes="{{ 'true' if cmd.has_changes else 'false' }}">
                <div class="command-header" onclick="toggleDiff(this)">
                    <span class="command-name">{{ cmd.command }}</span>
                    <div class="command-meta">
                        {% if cmd.has_changes %}
                        <span class="added">+{{ cmd.added_lines }}</span>
                        <span class="removed">-{{ cmd.removed_lines }}</span>
                        {% else %}
                        <span>No changes</span>
                        {% endif %}
                        <span class="toggle-icon">▼</span>
                    </div>
                </div>
                <div class="command-diff">
                    {% if cmd.has_changes %}
                    {{ cmd.diff_html | safe }}
                    {% else %}
                    <div class="no-changes">Output unchanged</div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    
    <script>
        function toggleDiff(header) {
            const card = header.closest('.command-card');
            card.classList.toggle('expanded');
            card.querySelector('.command-diff').classList.toggle('expanded');
        }
        
        function filterCommands(filter) {
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            document.querySelectorAll('.command-card').forEach(card => {
                const hasChanges = card.dataset.hasChanges === 'true';
                if (filter === 'all') {
                    card.style.display = 'block';
                } else if (filter === 'changed') {
                    card.style.display = hasChanges ? 'block' : 'none';
                } else {
                    card.style.display = hasChanges ? 'none' : 'block';
                }
            });
        }
        
        function toggleAll() {
            const cards = document.querySelectorAll('.command-card[data-has-changes="true"]');
            const anyExpanded = Array.from(cards).some(c => c.classList.contains('expanded'));
            
            cards.forEach(card => {
                if (anyExpanded) {
                    card.classList.remove('expanded');
                    card.querySelector('.command-diff').classList.remove('expanded');
                } else {
                    card.classList.add('expanded');
                    card.querySelector('.command-diff').classList.add('expanded');
                }
            });
        }
    </script>
</body>
</html>
"""


class OptimizedReportGenerator:
    """
    Generates optimized, paginated HTML reports for large-scale analysis.
    
    Instead of one huge file, generates:
    - Index page with device cards (paginated)
    - Individual device pages with collapsible command diffs
    """
    
    def __init__(self, masker: Optional[DataMasker] = None):
        """Initialize generator."""
        self.masker = masker or DataMasker()
        self.index_template = Template(INDEX_TEMPLATE)
        self.device_template = Template(DEVICE_TEMPLATE)
    
    def generate_report(
        self,
        change_number: str,
        device_diffs: List[DeviceDiff],
        output_dir: Path,
        devices_per_page: int = 50
    ) -> Path:
        """
        Generate optimized paginated report.
        
        Args:
            change_number: Change identifier
            device_diffs: List of device diff objects
            output_dir: Output directory for report files
            devices_per_page: Number of devices per index page
            
        Returns:
            Path to main index file
        """
        report_dir = output_dir / change_number
        devices_dir = report_dir / "devices"
        devices_dir.mkdir(parents=True, exist_ok=True)
        
        # Compute statistics
        stats = self._compute_stats(device_diffs)
        
        # Sort devices by status priority (errors first, then changed, then unchanged)
        status_order = {'errors': 0, 'changed': 1, 'unchanged': 2}
        sorted_diffs = sorted(
            device_diffs,
            key=lambda d: (
                status_order.get(self._get_device_status(d), 3),
                -d.commands_with_changes,
                d.hostname
            )
        )
        
        # Generate device pages
        device_summaries = []
        for device_diff in sorted_diffs:
            summary = self._generate_device_page(
                change_number, device_diff, devices_dir
            )
            device_summaries.append(summary)
        
        # Generate paginated index pages
        total_pages = (len(device_summaries) + devices_per_page - 1) // devices_per_page
        
        for page in range(1, total_pages + 1):
            start_idx = (page - 1) * devices_per_page
            end_idx = start_idx + devices_per_page
            page_devices = device_summaries[start_idx:end_idx]
            
            index_html = self.index_template.render(
                change_number=change_number,
                devices=page_devices,
                current_page=page,
                total_pages=total_pages,
                **stats
            )
            
            filename = "index.html" if page == 1 else f"index_{page}.html"
            (report_dir / filename).write_text(index_html, encoding='utf-8')
        
        return report_dir / "index.html"
    
    def _compute_stats(self, device_diffs: List[DeviceDiff]) -> Dict:
        """Compute aggregate statistics."""
        stats = {
            'total_devices': len(device_diffs),
            'changed_devices': 0,
            'error_devices': 0,
            'interface_changes': 0,
            'bgp_changes': 0,
            'ospf_changes': 0,
        }
        
        for dd in device_diffs:
            if dd.commands_with_changes > 0:
                stats['changed_devices'] += 1
            
            for cmd in dd.command_diffs:
                cmd_lower = cmd.command.lower()
                if cmd.has_changes:
                    if 'interface' in cmd_lower or 'ip int' in cmd_lower:
                        stats['interface_changes'] += 1
                    elif 'bgp' in cmd_lower:
                        stats['bgp_changes'] += 1
                    elif 'ospf' in cmd_lower:
                        stats['ospf_changes'] += 1
                
                # Check for errors
                if cmd.post_output and 'error' in cmd.post_output.lower():
                    stats['error_devices'] += 1
                    break
        
        return stats
    
    def _get_device_status(self, device_diff: DeviceDiff) -> str:
        """Determine device status."""
        has_errors = any(
            cmd.post_output and 'error' in cmd.post_output.lower()
            for cmd in device_diff.command_diffs
        )
        if has_errors:
            return 'errors'
        if device_diff.commands_with_changes > 0:
            return 'changed'
        return 'unchanged'
    
    def _generate_device_page(
        self,
        change_number: str,
        device_diff: DeviceDiff,
        output_dir: Path
    ) -> Dict:
        """Generate individual device page."""
        hostname = device_diff.hostname
        
        # Prepare command data with rendered diffs
        commands = []
        has_interface_changes = False
        has_bgp_changes = False
        has_ospf_changes = False
        
        for cmd in device_diff.command_diffs:
            cmd_lower = cmd.command.lower()
            
            if cmd.has_changes:
                if 'interface' in cmd_lower or 'ip int' in cmd_lower:
                    has_interface_changes = True
                elif 'bgp' in cmd_lower:
                    has_bgp_changes = True
                elif 'ospf' in cmd_lower:
                    has_ospf_changes = True
            
            # Generate diff HTML for this command
            diff_html = ""
            if cmd.has_changes:
                # Handle cases where pre or post might be empty (e.g., new errors appeared)
                pre_output = cmd.pre_output if cmd.pre_output else ""
                post_output = cmd.post_output if cmd.post_output else ""
                diff_html = self._generate_command_diff_html(pre_output, post_output)
            
            commands.append({
                'command': cmd.command,
                'has_changes': cmd.has_changes,
                'added_lines': cmd.added_lines,
                'removed_lines': cmd.removed_lines,
                'diff_html': diff_html
            })
        
        status = self._get_device_status(device_diff)
        
        # Render device page
        device_html = self.device_template.render(
            change_number=change_number,
            hostname=hostname,
            status=status,
            total_commands=device_diff.total_commands,
            commands_with_changes=device_diff.commands_with_changes,
            commands=commands
        )
        
        # Write device page
        device_file = output_dir / f"{hostname}.html"
        device_file.write_text(device_html, encoding='utf-8')
        
        # Return summary for index page
        return {
            'hostname': hostname,
            'status': status,
            'total_commands': device_diff.total_commands,
            'commands_with_changes': device_diff.commands_with_changes,
            'has_interface_changes': has_interface_changes,
            'has_bgp_changes': has_bgp_changes,
            'has_ospf_changes': has_ospf_changes,
        }
    
    def _generate_command_diff_html(self, pre: str, post: str) -> str:
        """Generate diff HTML for a single command."""
        pre_lines = pre.splitlines()
        post_lines = post.splitlines()
        
        diff = difflib.unified_diff(pre_lines, post_lines, lineterm='')
        
        html_lines = ['<table class="diff-table">']
        pre_line_num = 0
        post_line_num = 0
        
        for line in diff:
            if line.startswith('---') or line.startswith('+++'):
                continue
            elif line.startswith('@@'):
                # Parse line numbers
                parts = line.split()
                if len(parts) >= 3:
                    pre_info = parts[1]
                    post_info = parts[2]
                    pre_line_num = abs(int(pre_info.split(',')[0]))
                    post_line_num = abs(int(post_info.split(',')[0]))
                html_lines.append(f'<tr class="line-ctx"><td class="line-num"></td><td class="line-num"></td><td>{html.escape(line)}</td></tr>')
            elif line.startswith('-'):
                html_lines.append(f'<tr class="line-del"><td class="line-num">{pre_line_num}</td><td class="line-num"></td><td>{html.escape(line[1:])}</td></tr>')
                pre_line_num += 1
            elif line.startswith('+'):
                html_lines.append(f'<tr class="line-add"><td class="line-num"></td><td class="line-num">{post_line_num}</td><td>{html.escape(line[1:])}</td></tr>')
                post_line_num += 1
            else:
                html_lines.append(f'<tr class="line-ctx"><td class="line-num">{pre_line_num}</td><td class="line-num">{post_line_num}</td><td>{html.escape(line[1:] if line.startswith(" ") else line)}</td></tr>')
                pre_line_num += 1
                post_line_num += 1
        
        html_lines.append('</table>')
        return '\n'.join(html_lines)
