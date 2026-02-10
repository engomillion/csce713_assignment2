## Honeypot

- I chose the SSH protocol and used the Paramiko library to implement a simple SSH server that always rejects the authorization attemps.
- I ended up implementing my logging in `honeypot.py` and so deleted the `logger.py` template.
- Two files are created in the `logs/` folder as a result of logging: `ssh_honeypot.log` and `connections.jsonl`.
- All events like connections, disconnections, authorization attempts and errors are logged to the JSON file.
- The log file uses Paramiko's logging to log authorization attempts and exceptions that are thrown with creating the more detailed JSON file or creating connections

### To test
# Build and run
docker-compose build --no-cache honeypot
docker-compose up -d honeypot
#As needed:
docker-compose down

# Check logs
tail -f ./honeypot/logs/ssh_honeypot.log

# Test from another machine
ssh root@<docker-host-ip> -p 2222

#To test again after a rebuild, you need to reset the RSA key:
# From Windows PowerShell or Command Prompt:
ssh-keygen -R [docker-host-ip]:2222
