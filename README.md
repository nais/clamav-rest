# ClamAV REST API

A RESTful API for scanning files using ClamAV, written in Go.

## Features

- Scan files via HTTP PUT or POST requests
- Supports `application/octet-stream` and `multipart/form-data`
- Returns JSON scan results
- Metrics for requests and virus discoveries

## Usage

### Endpoints

- `POST /scan` — Upload a file using multipart form
- `PUT /scan` — Upload raw file data

### Example: Scan a file

```bash
curl -F "file=@yourfile.txt" http://localhost:8080/scan
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
