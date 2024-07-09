
# Integrity updater

This script will update the SubResource integrity (SRI) in the HTML files.

## Installation

```bash
pip install integrity-updater
```

## Usage

```bash
integrity-updater <html_file>
```

## Pre-commit configuration

```yaml
repos:
  - repo: https://github.com/sbrunner/integrity-updater
    rev: <version> # Use the ref you want to point at
    hooks:
      - id: integrity-updater

```
