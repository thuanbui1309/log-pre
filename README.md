# IPSec Log Parser

Parses StrongSwan/charon IPSec logs and groups lines into events.

## Usage

```bash
# Place .log files in data/ folder
uv run main.py
```

Output: `output/<filename>_events.json`

## Grouping Mechanism

Groups log lines by **Session Name** (e.g., `TTCH_BTLCSB[48]`)

### Example Input
```
12:12:14 05[IKE] initiating IKE_SA TTCH_BTLCSB[48] to 195.204.137.2
12:12:14 05[ENC] generating IKE_SA_INIT request 0 [...]
12:12:14 05[NET] sending packet: ... to 195.204.137.2 (714 bytes)
12:12:16 05[IKE] retransmit 2 of request with message ID 0
12:12:18 05[NET] sending packet: ... to 195.204.137.2 (714 bytes)
12:12:20 05[IKE] giving up after 5 retransmits
```

### Example Output
```json
{
  "session_name": "TTCH_BTLCSB[48]",
  "dest_ip": "195.204.137.2",
  "status": "timeout",
  "labels": {
    "log_type": "ipsec",
    "event_category": "ike",
    "status": "timeout"
  },
  "line_count": 6,
  "log_lines": [...]
}
```

## Correlation Methods

| Line Type | Correlation |
|-----------|-------------|
| `initiating IKE_SA X[N] to IP` | Creates event, maps IP→Session |
| `sending packet... to IP` | Lookup IP→Session |
| `retransmit N of request` | Uses thread→session mapping |
| `giving up after N retransmits` | Closes event via thread mapping |

## Event Status

- `success` - Session established
- `timeout` - Gave up after retransmits
- `auth_failure` - Authentication failed
- `incomplete` - Log ended before session finished
