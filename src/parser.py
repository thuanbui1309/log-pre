"""IPSec Log Parser - Groups log lines into events by session name."""

import re
import json
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from collections import defaultdict


@dataclass
class LogLine:
    line_num: int
    timestamp: str
    hostname: str
    facility: str
    process: str
    thread_id: str
    subsystem: str
    message: str
    raw: str
    remote_ip: Optional[str] = None
    session_name: Optional[str] = None


@dataclass
class Event:
    event_id: str
    session_name: str
    dest_ip: Optional[str]
    start_line: int
    end_line: Optional[int] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    lines: list = field(default_factory=list)
    status: str = "in_progress"
    error_detail: Optional[str] = None
    labels: dict = field(default_factory=dict)
    threads_involved: set = field(default_factory=set)


class IPSecLogParser:
    LOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<facility>\S+)\s+'
        r'(?P<process>\S+):\s+'
        r'(?P<thread_id>\d+)\[(?P<subsystem>\w+)\]\s+'
        r'(?P<message>.+)$'
    )
    
    IP_TO_PATTERN = re.compile(r'to\s+(\d+\.\d+\.\d+\.\d+)')
    IP_FROM_PATTERN = re.compile(r'from\s+(\d+\.\d+\.\d+\.\d+)')
    SESSION_PATTERN = re.compile(r'IKE_SA\s+(\S+)\[(\d+)\]')
    CHILD_SA_PATTERN = re.compile(r'CHILD_SA\s+(\S+)\{(\d+)\}')
    
    ERROR_PATTERNS = [
        ("giving up after", "timeout"),
        ("authentication failed", "auth_failure"),
        ("received AUTHENTICATION_FAILED", "auth_failure"),
        ("no proposal chosen", "proposal_mismatch"),
        ("certificate validation failed", "cert_error"),
        ("connection refused", "connection_error"),
    ]
    
    def __init__(self):
        self.parsed_lines: list[LogLine] = []
        self.events: list[Event] = []
        self.active_sessions: dict[str, Event] = {}
        self.ip_to_session: dict[str, str] = {}
        self.thread_to_session: dict[str, str] = {}
        self.event_counter = 0
        self.unattributed_lines: list[tuple[LogLine, str]] = []
        
    def parse_line(self, line_num: int, raw_line: str) -> Optional[LogLine]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None
            
        match = self.LOG_PATTERN.match(raw_line)
        if not match:
            return None
            
        groups = match.groupdict()
        message = groups['message']
        
        to_match = self.IP_TO_PATTERN.search(message)
        from_match = self.IP_FROM_PATTERN.search(message)
        
        if "received packet" in message:
            remote_ip = from_match.group(1) if from_match else None
        else:
            remote_ip = to_match.group(1) if to_match else None
        
        session_name = None
        session_match = self.SESSION_PATTERN.search(message)
        if session_match:
            session_name = f"{session_match.group(1)}[{session_match.group(2)}]"
        else:
            child_match = self.CHILD_SA_PATTERN.search(message)
            if child_match:
                session_name = f"{child_match.group(1)}{{{child_match.group(2)}}}"
        
        return LogLine(
            line_num=line_num,
            timestamp=groups['timestamp'],
            hostname=groups['hostname'],
            facility=groups['facility'],
            process=groups['process'],
            thread_id=groups['thread_id'],
            subsystem=groups['subsystem'],
            message=message,
            raw=raw_line,
            remote_ip=remote_ip,
            session_name=session_name,
        )
    
    def generate_event_id(self, session_name: str) -> str:
        self.event_counter += 1
        safe_name = session_name.replace('[', '_').replace(']', '').replace('{', '_').replace('}', '')
        return f"{safe_name}_{self.event_counter}"
    
    def finalize_event(self, event: Event, status: str, error_detail: Optional[str] = None):
        event.status = status
        event.error_detail = error_detail
        
        if event.lines:
            event.end_line = event.lines[-1].line_num
            event.end_time = event.lines[-1].timestamp
        
        event.labels = {
            'log_type': 'ipsec',
            'event_category': 'ike',
            'status': status,
        }
        if error_detail:
            event.labels['error_type'] = error_detail
        
        self.events.append(event)
    
    def find_session_for_line(self, log_line: LogLine) -> Optional[str]:
        if log_line.session_name and log_line.session_name in self.active_sessions:
            return log_line.session_name
        
        if log_line.remote_ip and log_line.remote_ip in self.ip_to_session:
            session_name = self.ip_to_session[log_line.remote_ip]
            if session_name in self.active_sessions:
                return session_name
        
        if log_line.thread_id in self.thread_to_session:
            session_name = self.thread_to_session[log_line.thread_id]
            if session_name in self.active_sessions:
                return session_name
        
        return None
    
    def process_line(self, log_line: LogLine):
        thread_id = log_line.thread_id
        remote_ip = log_line.remote_ip
        message = log_line.message
        
        # Session start
        if "initiating IKE_SA" in message and log_line.session_name:
            session_name = log_line.session_name
            
            if session_name in self.active_sessions:
                event = self.active_sessions[session_name]
                event.lines.append(log_line)
                event.threads_involved.add(thread_id)
            else:
                event = Event(
                    event_id=self.generate_event_id(session_name),
                    session_name=session_name,
                    dest_ip=remote_ip,
                    start_line=log_line.line_num,
                    start_time=log_line.timestamp,
                    lines=[log_line],
                    threads_involved={thread_id},
                )
                self.active_sessions[session_name] = event
            
            if remote_ip:
                self.ip_to_session[remote_ip] = session_name
            self.thread_to_session[thread_id] = session_name
            return
        
        # Session success
        if "established" in message and log_line.session_name:
            session_name = log_line.session_name
            
            target_session = None
            if session_name in self.active_sessions:
                target_session = session_name
            elif remote_ip and remote_ip in self.ip_to_session:
                target_session = self.ip_to_session[remote_ip]
            
            if target_session and target_session in self.active_sessions:
                event = self.active_sessions[target_session]
                event.lines.append(log_line)
                event.threads_involved.add(thread_id)
                self.finalize_event(event, 'success')
                del self.active_sessions[target_session]
            else:
                event = Event(
                    event_id=self.generate_event_id(session_name),
                    session_name=session_name,
                    dest_ip=remote_ip,
                    start_line=log_line.line_num,
                    start_time=log_line.timestamp,
                    lines=[log_line],
                    threads_involved={thread_id},
                )
                self.finalize_event(event, 'success')
            return
        
        # Session error
        for pattern, error_type in self.ERROR_PATTERNS:
            if pattern in message:
                target_session = self.thread_to_session.get(thread_id)
                
                if target_session and target_session in self.active_sessions:
                    event = self.active_sessions[target_session]
                    event.lines.append(log_line)
                    event.threads_involved.add(thread_id)
                    self.finalize_event(event, error_type, error_type)
                    del self.active_sessions[target_session]
                else:
                    self.unattributed_lines.append((log_line, f"No active session for thread {thread_id}"))
                return
        
        # Continuation
        target_session = self.find_session_for_line(log_line)
        
        if target_session:
            event = self.active_sessions[target_session]
            event.lines.append(log_line)
            event.threads_involved.add(thread_id)
            self.thread_to_session[thread_id] = target_session
        else:
            reason = f"No session for IP {remote_ip}" if remote_ip else f"No IP, thread {thread_id}"
            self.unattributed_lines.append((log_line, reason))
    
    def parse_file(self, file_path: str) -> list[Event]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        print(f"Parsing: {path.name}")
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                parsed = self.parse_line(line_num, line)
                if parsed:
                    self.parsed_lines.append(parsed)
                    self.process_line(parsed)
        
        for session_name, event in list(self.active_sessions.items()):
            self.finalize_event(event, 'incomplete')
        self.active_sessions.clear()
        
        print(f"Parsed {len(self.parsed_lines)} lines -> {len(self.events)} events")
        
        return self.events
    
    def get_statistics(self) -> dict:
        stats = {
            'total_lines': len(self.parsed_lines),
            'total_events': len(self.events),
            'unattributed_lines': len(self.unattributed_lines),
            'attribution_rate': round((1 - len(self.unattributed_lines) / len(self.parsed_lines)) * 100, 1) if self.parsed_lines else 0,
            'by_status': defaultdict(int),
            'by_error_type': defaultdict(int),
            'unique_sessions': set(),
            'unique_dest_ips': set(),
        }
        
        for event in self.events:
            stats['by_status'][event.status] += 1
            if event.error_detail:
                stats['by_error_type'][event.error_detail] += 1
            if event.session_name:
                stats['unique_sessions'].add(event.session_name.split('[')[0].split('{')[0])
            if event.dest_ip:
                stats['unique_dest_ips'].add(event.dest_ip)
        
        stats['unique_session_count'] = len(stats['unique_sessions'])
        stats['unique_dest_ip_count'] = len(stats['unique_dest_ips'])
        del stats['unique_sessions']
        del stats['unique_dest_ips']
        stats['by_status'] = dict(stats['by_status'])
        stats['by_error_type'] = dict(stats['by_error_type'])
        
        return stats
    
    def export_to_json(self, output_path: str):
        output = {
            'metadata': {
                'parser_version': '3.0.0',
                'grouping_strategy': 'session_name',
                'generated_at': datetime.now().isoformat(),
                'statistics': self.get_statistics(),
            },
            'events': [],
            'unattributed_lines': []
        }
        
        for event in self.events:
            output['events'].append({
                'event_id': event.event_id,
                'session_name': event.session_name,
                'dest_ip': event.dest_ip,
                'threads_involved': list(event.threads_involved),
                'start_line': event.start_line,
                'end_line': event.end_line,
                'start_time': event.start_time,
                'end_time': event.end_time,
                'status': event.status,
                'error_detail': event.error_detail,
                'labels': event.labels,
                'line_count': len(event.lines),
                'log_lines': [
                    {
                        'line_num': line.line_num,
                        'timestamp': line.timestamp,
                        'thread_id': line.thread_id,
                        'subsystem': line.subsystem,
                        'message': line.message,
                    }
                    for line in event.lines
                ]
            })
        
        for log_line, reason in self.unattributed_lines:
            output['unattributed_lines'].append({
                'line_num': log_line.line_num,
                'thread_id': log_line.thread_id,
                'remote_ip': log_line.remote_ip,
                'session_name': log_line.session_name,
                'reason': reason,
                'message': log_line.message,
            })
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        print(f"Exported: {output_path}")
