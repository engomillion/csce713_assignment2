# Honeypot Analysis

This Honeypot is a simple implementation that allows an attacker to attempt to log in but will not allow authentication. It offers the attacker a legitimate banner and an RSA key to avoid suspicion. It also has some minimal security features to mimic expected behavior from an SSH server, like only allowing three attempts in a row before rejecting the connection, though it will allow the attacker to attempt again to log in from the same IP address. Since all of these attempts are programmed to fail, this means an attacker will have to reestablish the ssh connection every three attempts.

## Summary of Observed Attacks

Since I did not make this docker open to the internet, I created my own attacks via my Windows and Virtual Machines. Each of the attacks was correctly logged.

## Notable Patterns

All of the attacks from the same machine had the same IP address, though this could be altered via IP spoofing. Source ports were the same for each of the three attempts before getting rejected by the SSH server. Subsequent attacks from the Windows machine incremented the source port by one if that subsequent attack was done soon after the previous attack. My Ubuntu machine did a better job of randomly choosing ports.

## Recommendations

For minimal expense, this Honeypot can identify attackers' IP addresses. Since no meaningful interaction is implemented in this system, that IP address should be blocked via the firewall to everything except maybe the Honeypot. You can observe how the attacker attempts to brute force usernames and passwords, and then ensure the rest of your system is not vulnerable to the attempted brute forcing.

