## Port Knocking

### What I implemented
- I picked port 2222 to protect.
- I used the default knock sequence (e.g., 1234, 5678, 9012).
- I implemented a server in `knock_server.py` that uses the Python library subprocess to write to iptables, which listens for knocks and validates the sequence.
- The protected port opens only after a valid sequence.
- I set a reset time of 10 seconds between knocks.
- I used the client template to send the knock sequence.

### To test
- Run from the repo root with `docker compose up port_knocking`.
- Run in the port_knocking directory: `demo.sh`
