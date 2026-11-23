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

V2 returns HTTP **503 Service Unavailable** if any file fails to scan, including
daemon connection failures and invalid or error responses. The JSON array still
includes every file's result, including successful scans in the same request.
If the daemon closes the connection without answering, V2 returns HTTP **503**
with `"result":"ERROR"` and `"error":"Invalid response"`.
Each V2 file scan sets a **90-second** deadline, which bounds the daemon response
read. An earlier request deadline takes precedence. Read timeouts return HTTP
**503** with `"result":"ERROR"` and `"error":"Scan failure"`.
Completed scans return HTTP **200 OK**, including when a virus is found.
V1 behavior and file handling are unchanged; no file retention or retries are added.

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

When a scan error occurs (HTTP **503 Service Unavailable**):
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

- Go 1.26 or later
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
- `-max-file-size` - Max upload size accepted by scan endpoints (default: `400Mi`, accepts units like `Mi`, `M`, `Gi`)
### Test

```bash
make test
``` 
