# Architecture

Findings are immutable-style dataclasses passed from discovery through classification and reports. SQLite stores scan sessions and normalized findings with indexes on names, scores, and scan IDs. Network failures are isolated per URL.
