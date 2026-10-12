# crypto-mini-project

- 2026-10-12 | **fact**: Built Flask+SQLite secure student portal: 5 fields -> 10 cells (AES-256-CBC enc + SHA256), sap_id as login ID, strong 12-char password, pluggable CryptoProvider (backend crypto_utils.py + frontend static/crypto.js) with algo+key_version per payload/row for future encryption swap.
- 2026-10-12 | **fact**: Split portal into 2 servers: FD fd_server.py :5000 (pages only, no DB import) and BD bd_server.py :5001 (API+SQLite only, no templates, flask-cors for FD origin); frontend fetch uses absolute BD_URL injected by FD.
- 2026-10-12 | **fact**: Fixed BD 'no such table' crash (0-byte students.db, likely OneDrive truncation): added database.ensure_db() self-heal before every BD request + JSON 500 handler. Added file logging: logs/bd_server.log (register/login/integrity events, hash-prefixes only) and logs/fd_server.log (pages served).
