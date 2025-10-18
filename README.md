# wormhole-cli

Command-line tool for [wormhole.app](https://wormhole.app) - upload, download, and inspect files.

## Installation

```bash
cargo install --git https://github.com/trumank/wormhole-cli.git
```

## Usage

### Upload files or directories
```bash
wormhole-cli upload <FILE_OR_DIR>
```

### Download files
```bash
wormhole-cli download <URL> [-o <OUTPUT_DIR>]
```

### Show file info
```bash
wormhole-cli info <URL>
```

## Examples

```bash
# Upload a file
wormhole-cli upload document.pdf

# Upload a directory
wormhole-cli upload my-folder/

# Download to current directory
wormhole-cli download https://wormhole.app/abc123#key

# Download to specific directory
wormhole-cli download https://wormhole.app/abc123#key -o ~/Downloads

# Check file info before downloading
wormhole-cli info https://wormhole.app/abc123#key

# Replace existing files without prompting
wormhole-cli download https://wormhole.app/abc123#key -r
```

## Options

### Upload
- `-v, --verbose` - Show detailed output

### Download
- `-o, --output <DIR>` - Output directory (default: current directory)
- `-v, --verbose` - Show detailed output
- `-r, --replace` - Replace existing files without prompting

### Info
- `-v, --verbose` - Show detailed output
