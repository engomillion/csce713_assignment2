#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import time
import subprocess

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10
TARGET_CONTAINER = '2_network_secret_ssh'



def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def open_protected_port(protected_port):
    """Open the protected port using firewall rules."""
    try:
        result = subprocess.run([
            'docker', 'exec', TARGET_CONTAINER,
            'iptables', '-A', 'INPUT',
            '-p', 'tcp',
            '--dport', str(protected_port),
            '-m', 'recent',
            '--name', 'knock3',
            '--rcheck',
            '-j', 'ACCEPT'
        ], 
        capture_output=True,
        text=True,
        check=True
        )
        logging.info(f"Knock3 on opened {protected_port}")
        logging.info(result.stdout)
        
    except subprocess.CalledProcessError as e:
        logging.info(f"Error: {e.stderr}")
        
    except PermissionError:
        logging.info("Error: Need root privileges (use sudo)")
        sys.exit(1)
    # TODO: Use iptables/nftables to allow access to protected_port.
    logging.info("TODO: Open firewall for port %s", protected_port)


def close_protected_port(protected_port):
    """Close the protected port using firewall rules."""
    logger = logging.getLogger("KnockServer")
    try:
        result = subprocess.run([
            'docker', 'exec', TARGET_CONTAINER,
            'iptables', '-A', 'INPUT',
            '-p', 'tcp',
            '--dport', str(protected_port),
            '-j', 'REJECT'
        ], 
        capture_output=True,
        text=True,
        check=True
        )
        logging.info(f"Port {protected_port} closed for all ips")
        logging.info(result.stdout)
        
    except subprocess.CalledProcessError as e:
        logging.info(f"Error: {e.stderr}")
        
    except PermissionError:
        logging.info("Error: Need root privileges (use sudo)")
        sys.exit(1)
    logging.info(result.stdout)


def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)
    try:
        result = subprocess.run([
            'docker', 'exec', TARGET_CONTAINER,
            'iptables', '-A', 'INPUT',
            '-p', 'tcp',
            '--dport', str(sequence[0]),
            '-m', 'recent',
            '--name', 'knock1',
            '--set',
            '-j', 'REJECT'
        ], 
        capture_output=True,
        text=True,
        check=True
        )
        logging.info(f"Knock on {sequence[0]} ")
        logging.info(result.stdout)
        
    except subprocess.CalledProcessError as e:
        logging.info(f"Error: {e.stderr}")
        
    except PermissionError:
        logging.info("Error: Need root privileges (use sudo)")
        sys.exit(1)
        
    try:
        result = subprocess.run([
            'docker', 'exec', TARGET_CONTAINER,
            'iptables', '-A', 'INPUT',
            '-p', 'tcp',
            '--dport', str(sequence[1]),
            '-m', 'recent',
            '--name', 'knock1',
            '--rcheck',
            '--seconds', str(window_seconds),
            '-m', 'recent',
            '--name', 'knock2',
            '--set',
            '-j', 'REJECT'
        ], 
        capture_output=True,
        text=True,
        check=True
        )
        logging.info(f"Knock on {sequence[1]} ")
        logging.info(result.stdout)
        
    except subprocess.CalledProcessError as e:
        logging.info(f"Error: {e.stderr}")
        
    except PermissionError:
        logging.info("Error: Need root privileges (use sudo)")
        sys.exit(1)
    try:
        result = subprocess.run([
            'docker', 'exec', TARGET_CONTAINER,
            'iptables', '-A', 'INPUT',
            '-p', 'tcp',
            '--dport', str(sequence[2]),
            '-m', 'recent',
            '--name', 'knock2',
            '--rcheck',
            '--seconds', str(window_seconds),
            '-m', 'recent',
            '--name', 'knock3',
            '--set',
            '-j', 'REJECT'
        ], 
        capture_output=True,
        text=True,
        check=True
        )
        logging.info(f"Knock on {sequence[2]} ")
        logging.info(result.stdout)
        
    except subprocess.CalledProcessError as e:
        logging.info(f"Error: {e.stderr}")
        
    except PermissionError:
        logging.info("Error: Need root privileges (use sudo)")
        sys.exit(1)
        
    open_protected_port(protected_port) 
    close_protected_port(protected_port) 
    
    # TODO: Create UDP or TCP listeners for each knock port.
    # TODO: Track each source IP and its progress through the sequence.
    # TODO: Enforce timing window per sequence.
    # TODO: On correct sequence, call open_protected_port().
    # TODO: On incorrect sequence, reset progress.

    while True:
        time.sleep(1)


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    logger = logging.getLogger("KnockServer")
    
    
    try:
        result = subprocess.run([
            'docker', 'exec', TARGET_CONTAINER,
            'iptables', '-F', 'INPUT'
        ], 
        capture_output=True,
        text=True,
        check=True
        )
        logging.info(f"Rules cleared")
        logging.info(result.stdout)
        
    except subprocess.CalledProcessError as e:
        logging.info(f"Error: {e.stderr}")
        
    except PermissionError:
        logging.info("Error: Need root privileges (use sudo)")
        sys.exit(1)

    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()
