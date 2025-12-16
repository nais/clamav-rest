# ClamAV REST API

A RESTful API for scanning files using ClamAV, written in Go.

## Features

- Scan files via HTTP PUT or POST requests
- Supports `application/octet-stream` and `multipart/form-data`
- Returns JSON scan results
- Metrics for requests and virus discoveries

## Usage

### Endpoints

#### V1 API
- `POST /scan` — Upload a file using multipart form
- `PUT /scan` — Upload raw file data

#### V2 API (Enhanced)
- `POST /api/v2/scan` — Upload a file using multipart form (with virus details)
- `PUT /api/v2/scan` — Upload raw file data (with virus details)

The v2 API returns additional fields:
- `virus` — Name of the detected virus (empty if clean)
- `error` — Error message if scan failed (empty if successful)
- Uses lowercase field names for consistency

Possible error values:
- `"Invalid response"` — ClamAV returned an unexpected response
- `"Scan failure"` — Failed to scan the file
- `"Unknown command"` — ClamAV doesn't recognize the command
- `"Unsupported command"` — Command is not supported by ClamAV

### Example: Scan a file

**V1 API:**
```bash
curl -F "file=@yourfile.txt" http://localhost:8080/scan
```

Response:
```json
[
  {
    "Filename": "yourfile.txt",
    "Result": "OK"
  }
]
```

**V2 API:**
```bash
curl -F "file=@yourfile.txt" http://localhost:8080/api/v2/scan
```

Response:
```json
[
  {
    "filename": "yourfile.txt",
    "result": "OK",
    "virus": "",
    "error": ""
  }
]
```

When a virus is detected:
```json
[
  {
    "filename": "eicar.com",
    "result": "FOUND",
    "virus": "EICAR-TEST-STRING",
    "error": ""
  }
]
```

When a scan error occurs:
```json
[
  {
    "filename": "corrupted.file",
    "result": "ERROR",
    "virus": "",
    "error": "Scan failure"
  }
]
```

## Development

### Prerequisites

- Go 1.25 or later
- ClamAV daemon installed and running
- Make 

### Build and Run

```bash
make build
./clamav-rest
```

#### Available flags
- `-bind-address` - Address to bind the server to (default ":8080")
- `-daemon-endpoint` - Host where ClamAV daemon is running (default: `localhost:3310`)
- `-log-level` - Log level (default: `info`)
- `-timeout` - Client connection timeout in seconds (default: `3`)
- `-keepalive` - Client connection keepalive (default: `3`)
- 
### Test

```bash
make test
``` 
