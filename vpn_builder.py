import argparse
import ipaddress
import sys
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path

# --- Constants and Embedded Config ---

IKEV2_CRYPTO = '''Phase1
crypto ikev2 policy 1
 encryption aes-256
 integrity sha256
 group 14
 prf sha256
 lifetime seconds 86400

Phase2
crypto ipsec ikev2 ipsec-proposal AES256-SHA256
 protocol esp encryption aes-256
 protocol esp integrity sha-256
'''

# Configuration Defaults
DEFAULT_SRC_NAME = 'VPN-SOURCE-LOCAL'
DEFAULT_INSIDE_IFACE = 'Inside'
DEFAULT_OUTSIDE_IFACE = 'Outside'
DEFAULT_CRYPTO_MAP_NAME = 'outside_map'


# --- Helper Functions for Validation ---

def _validate_ip_entries(entries: List[str], entry_type: str) -> Tuple[List[str], List[str]]:
    """Validates a list of network strings and returns valid/invalid lists."""
    valid = []
    invalid = []
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            valid.append(str(net))
        except ValueError:
            invalid.append(entry)
    
    if not valid:
        # Note: We exit here because without valid networks, the config cannot be generated.
        print(f"Error: No valid {entry_type} networks were provided.", file=sys.stderr)
        sys.exit(2)
        
    return valid, invalid


def _validate_peer_ip(peer_input: str, allow_private: bool) -> str:
    """Validates the peer IP address for public IPv4 /32."""
    if not peer_input:
        raise ValueError("Peer IP address is required.")

    addr = None
    peer_reason = None
    
    # ... (Peer validation logic remains the same) ...
    try:
        if "/" in peer_input:
            peer_net = ipaddress.ip_network(peer_input, strict=False)
            if peer_net.version != 4:
                peer_reason = 'not an IPv4 network'
            elif peer_net.prefixlen != 32:
                peer_reason = 'network prefix is not /32'
            elif peer_net.num_addresses != 1:
                peer_reason = 'network contains multiple addresses'
            else:
                addr = peer_net.network_address
        else:
            candidate = ipaddress.ip_address(peer_input)
            if candidate.version != 4:
                peer_reason = 'not an IPv4 address'
            else:
                addr = candidate

        if addr is not None and peer_reason is None:
            if allow_private:
                return str(addr)
            
            # Require public/global IPv4
            if getattr(addr, 'is_global', False):
                return str(addr)
            else:
                peer_reason = 'address is not a public/global IPv4 address'
        
    except ValueError:
        peer_reason = 'invalid IP format'

    raise ValueError(f"Invalid peer IP ({peer_input}): {peer_reason}")


# --- Configuration Generation Functions (Kept as is) ---

def _format_object_group(group_name: str, networks: List[str]) -> str:
    # ... (Implementation kept as is) ...
    lines = [f"object-group network {group_name}"]
    for n in networks:
        try:
            net = ipaddress.ip_network(n, strict=False)
            addr = str(net.network_address)
            
            if net.version == 4:
                if net.prefixlen == 32:
                    lines.append(f" network-object host {addr}")
                else:
                    netmask = str(net.netmask)
                    lines.append(f" network-object {addr} {netmask}")
            else:
                lines.append(f" ! skipping IPv6 entry: {n}")
        except ValueError:
            lines.append(f" ! invalid entry skipped: {n}")
    return "\n".join(lines)


def _generate_access_list(acl_name: str, src_name: str, dst_name: str) -> str:
    return f"access-list {acl_name} extended permit ip object-group {src_name} object-group {dst_name}"


def _generate_nat_statement(nat_inside: str, nat_outside: str, src_name: str, dst_name: str) -> str:
    return (
        f"nat ({nat_inside},{nat_outside}) source static {src_name} {src_name} "
        f"destination static {dst_name} {dst_name} no-proxy-arp route-lookup"
    )


def _generate_crypto_map(crypto_map_name: str, crypto_map_seq: int, acl_name: str, peer_ip: str) -> str:
    """Generates the crypto map lines."""
    lines = [
        f"crypto map {crypto_map_name} {crypto_map_seq} match address {acl_name}",
        f"crypto map {crypto_map_name} {crypto_map_seq} set peer {peer_ip}",
        f"crypto map {crypto_map_name} {crypto_map_seq} set ikev2 ipsec-proposal AES256-SHA256",
        f"crypto map {crypto_map_name} {crypto_map_seq} set security-association lifetime seconds 28800"
    ]
    return "\n".join(lines)


def _generate_tunnel_group(peer_ip: str, pre_shared_key: str) -> str:
    """Generates the tunnel-group configuration block."""
    lines = [
        f"tunnel-group {peer_ip} type ipsec-l2l",
        f"tunnel-group {peer_ip} ipsec-attributes",
        f" ikev2 remote-authentication pre-shared-key {pre_shared_key}",
        f" ikev2 local-authentication pre-shared-key {pre_shared_key}"
    ]
    return "\n".join(lines)


# --- Core Logic Functions ---

def get_required_inputs(cli_args: argparse.Namespace) -> Dict[str, Any]:
    """
    Handles all input retrieval (CLI or interactive prompt) and ensures 
    mandatory fields are set, prompting interactively if not provided via CLI.
    """
    data = {}
    
    # --- Check for Non-Interactive/CLI Mode ---
    # We assume non-interactive mode if key arguments (sources, destinations) are provided.
    is_cli_mode = bool(cli_args.sources and cli_args.destinations)

    # --- Input Handling ---
    
    # Source Networks
    source_input = cli_args.sources
    if not source_input: 
        source_input = input("Enter source network(s) (CIDR or subnet mask, comma-separated): ").strip()
    data['sources'] = [entry.strip() for entry in source_input.split(",") if entry.strip()]
    
    # Destination Networks
    dest_input = cli_args.destinations
    if not dest_input:
        dest_input = input("\nEnter destination networks (comma-separated): ").strip()
    data['destinations'] = [entry.strip() for entry in dest_input.split(",") if entry.strip()]

    # Peer IP
    peer_input = str(cli_args.peer).strip() if cli_args.peer is not None else None
    if not peer_input:
        peer_input = input("\nEnter peer IP address (IPv4 host or IPv4/32): ").strip()
    data['peer_input'] = peer_input

    # Source Object-Group Name
    data['src_name'] = cli_args.src_name if cli_args.src_name else input(f"Enter source object-group name [{DEFAULT_SRC_NAME}]: ").strip() or DEFAULT_SRC_NAME
    
    # Destination Name Input (used to format the full group/ACL name)
    dst_name_input = cli_args.dst_name
    if not dst_name_input:
        while True:
            dst_name_input = input("Enter destination name (will be formatted as VPN-{name}-REMOTE): ").strip()
            if dst_name_input: break
            print("Destination name is required. Please enter a name.")
    data['dst_name_input'] = dst_name_input.upper()

    # NAT Interfaces
    data['nat_inside'] = cli_args.nat_inside if cli_args.nat_inside else input(f"\nEnter NAT Inside interface name [{DEFAULT_INSIDE_IFACE}]: ").strip() or DEFAULT_INSIDE_IFACE
    data['nat_outside'] = cli_args.nat_outside if cli_args.nat_outside else input(f"Enter NAT Outside interface name [{DEFAULT_OUTSIDE_IFACE}]: ").strip() or DEFAULT_OUTSIDE_IFACE

    # Crypto Map Name
    data['crypto_map_name'] = cli_args.crypto_map_name if cli_args.crypto_map_name else input(f"\nEnter crypto map name [{DEFAULT_CRYPTO_MAP_NAME}]: ").strip() or DEFAULT_CRYPTO_MAP_NAME

    # Crypto Map Sequence (Always required for full config)
    data['crypto_map_seq'] = None
    if cli_args.crypto_map_seq is not None:
        try:
            data['crypto_map_seq'] = int(cli_args.crypto_map_seq)
        except ValueError:
            raise ValueError("Crypto map sequence (--crypto-map-seq) must be a valid integer.")
    else:
        while data['crypto_map_seq'] is None:
            seq_input = input("Enter crypto map sequence number (required, integer): ").strip()
            try:
                data['crypto_map_seq'] = int(seq_input)
            except ValueError:
                print("Invalid input. Please enter a valid integer.")
                
    # Pre-shared Key (Always required for full config)
    data['pre_shared_key'] = cli_args.pre_shared_key
    if not data['pre_shared_key']:
        while True:
            data['pre_shared_key'] = input("\nEnter pre-shared key (required, non-empty): ").strip()
            if data['pre_shared_key']: break
            print("Pre-shared key is required. Please enter a value.")
            
    return data

def validate_and_process_inputs(data: Dict[str, Any], cli_args: argparse.Namespace) -> Dict[str, Any]:
    """Performs strict validation on networks and peer IP."""
    
    # 1. Network Validation
    data['valid_sources'], invalid_sources = _validate_ip_entries(data['sources'], 'source')
    data['valid_destinations'], invalid_destinations = _validate_ip_entries(data['destinations'], 'destination')

    # Display validation results
    print("\n--- Network Validation Results ---")
    print(f"✅ Valid source networks: {len(data['valid_sources'])} found.")
    for net in invalid_sources: print(f"❌ Invalid source entry skipped: {net}")
    print(f"\n✅ Valid destination networks: {len(data['valid_destinations'])} found.")
    for net in invalid_destinations: print(f"❌ Invalid destination entry skipped: {net}")
    print("----------------------------------")

    # 2. Peer IP Validation
    data['peer_value'] = _validate_peer_ip(data['peer_input'], cli_args.allow_private_peer)
    print(f"\n✅ Valid Peer IP: {data['peer_value']}")
    
    return data


def generate_full_config(data: Dict[str, Any]) -> Tuple[str, str, str]:
    """Orchestrates the generation of all configuration blocks."""
    
    # Finalize names
    src_name = data['src_name'].upper()
    dst_name_input = data['dst_name_input'].upper()
    dst_name = f"VPN-{dst_name_input}-REMOTE"
    acl_name = f"TO-{dst_name_input}-VPN"
    
    # 1. Object Groups
    src_block = _format_object_group(src_name, data['valid_sources'])
    dst_block = _format_object_group(dst_name, data['valid_destinations'])
    
    # 2. Access-list
    acl_line = _generate_access_list(acl_name, src_name, dst_name)
    
    # 3. NAT Statement
    nat_line = _generate_nat_statement(data['nat_inside'], data['nat_outside'], src_name, dst_name)
    
    # 4. Crypto Map
    crypto_map_output = _generate_crypto_map(
        data['crypto_map_name'], data['crypto_map_seq'], acl_name, data['peer_value']
    )
    
    # 5. Tunnel Group
    tunnel_group_output = _generate_tunnel_group(data['peer_value'], data['pre_shared_key'])
    
    # 6. Assemble Final Output
    config_parts = [
        "--- Generated Object Groups ---",
        src_block,
        dst_block,
        "\n--- Access-list ---",
        acl_line,
        "\n--- NAT Exemption ---",
        nat_line,
        "\n--- Crypto Map Configuration ---",
        crypto_map_output,
        "\n--- Tunnel Group Configuration ---",
        tunnel_group_output,
    ]
    
    full_config_string = "\n\n".join(config_parts)
    
    return full_config_string, og_config, dst_name


def save_config_to_file(file_path: str, config_content: str):
    """Saves the configuration content to a file using pathlib."""
    try:
        Path(file_path).write_text(config_content + "\n")
        print(f"\nSaved full configuration to: {file_path}")
    except OSError as e:
        print(f"\nFailed to write file: {e}", file=sys.stderr)


# --- Argument Parsing (Updated) ---

def _build_arg_parser():
    p = argparse.ArgumentParser(
        description='Create IPSec VPN configuration for Cisco ASA.',
        epilog='''
The script automatically generates the full VPN configuration whenever valid inputs are provided.

REQUIRED ARGUMENTS (for non-interactive CLI usage):
  -s, --sources, -d, --destinations, -dn, --dst-name, 
  -cms, --crypto-map-seq, -psk, --pre-shared-key, -p, --peer
  
Run the script without any arguments to enter interactive mode.
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument('--sources', '-s', help='Comma-separated source networks (CIDR or subnet mask)')
    p.add_argument('--destinations', '-d', help='Comma-separated destination networks')
    p.add_argument('--peer', '-p', help='Peer IP (IPv4 host or /32)')
    # REMOVED: '--create-object-groups', '-c'
    p.add_argument('--src-name', '-sn', help='Source object-group name')
    p.add_argument('--dst-name', '-dn', help='Destination object-group name (REQUIRED)')
    p.add_argument('--output', '-o', help='File path to save configuration')
    p.add_argument('--allow-private-peer', '-ap', dest='allow_private_peer', action='store_true', help='Allow private/non-global peer addresses')
    p.add_argument('--print-crypto', '-pc', dest='print_crypto', action='store_true', help='Print the embedded IKEv2 crypto config included in this script')
    p.add_argument('--nat-inside', '-ni', dest='nat_inside', help=f'NAT Inside interface name (default: {DEFAULT_INSIDE_IFACE})')
    p.add_argument('--nat-outside', '-no', dest='nat_outside', help=f'NAT Outside interface name (default: {DEFAULT_OUTSIDE_IFACE})')
    p.add_argument('--crypto-map-name', '-cmn', dest='crypto_map_name', help=f'Crypto map name (default: {DEFAULT_CRYPTO_MAP_NAME})')
    p.add_argument('--crypto-map-seq', '-cms', dest='crypto_map_seq', help='Crypto map sequence number (REQUIRED)')
    p.add_argument('--pre-shared-key', '-psk', dest='pre_shared_key', help='Pre-shared key for tunnel-group (REQUIRED)')
    return p


# --- Main Execution Block (Orchestration) ---

if __name__ == "__main__":
    parser = _build_arg_parser()
    args = parser.parse_args()

    try:
        # Step 1: Get all inputs (CLI or Interactive)
        # Note: If running in CLI mode, get_required_inputs will fail quickly
        # if a REQUIRED argument is missing.
        config_data = get_required_inputs(args)
        
        # Step 2: Perform Validation
        config_data = validate_and_process_inputs(config_data, args)
        
        # Step 3: Generate Configuration
        # Configuration is now generated automatically after successful validation
        full_config, _, _ = generate_full_config(config_data)

        # Step 4: Display Output
        print("\n" + "="*50)
        print("GENERATED CISCO ASA VPN CONFIGURATION")
        print("="*50)
        print(full_config)
        print("\n" + "="*50)

        # Print Crypto Config
        # Now prints if requested OR if running non-interactively without specifying an output file
        is_cli_no_output = (args.sources and not args.output) 
        if args.print_crypto or is_cli_no_output:
            print('\n--- Recommended IKEv2 Crypto Config ---\n')
            print(IKEV2_CRYPTO.rstrip())

        # Step 5: Handle Saving
        save_path = args.output
        if not args.sources and not args.output:
            # Only prompt to save if running interactively and no output file was specified
            save_path = input("\nSave full configuration to file? (enter path or leave blank to skip): ").strip()

        if save_path:
            save_config_to_file(save_path, full_config)

    except (ValueError, FileNotFoundError) as e:
        print(f"\n❌ FATAL ERROR: {e}", file=sys.stderr)
        sys.exit(2)