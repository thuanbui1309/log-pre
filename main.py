"""Log analysis entry point."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.parser import IPSecLogParser


def main():
    data_dir = Path(__file__).parent / "data"
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)
    
    log_files = list(data_dir.glob("*.log"))
    
    if not log_files:
        print("No .log files found in data/")
        return 1
    
    print(f"Found {len(log_files)} log file(s)\n")
    
    for log_file in log_files:
        parser = IPSecLogParser()
        events = parser.parse_file(str(log_file))
        stats = parser.get_statistics()
        
        print(f"\nStatistics:")
        print(f"  Lines: {stats['total_lines']}")
        print(f"  Events: {stats['total_events']}")
        print(f"  Unattributed: {stats['unattributed_lines']}")
        print(f"  Attribution rate: {stats.get('attribution_rate', 0)}%")
        
        print(f"\nBy status:")
        for status, count in stats['by_status'].items():
            print(f"  {status}: {count}")
        
        output_file = output_dir / f"{log_file.stem}_events.json"
        parser.export_to_json(str(output_file))
    
    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
