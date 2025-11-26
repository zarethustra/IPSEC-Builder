import argparse
import ipaddress
import sys
import re
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path

# --- Constants and Embedded Config ---

# Configuration Defaults and Constants consolidated into one dictionary
TUNNEL_DEFAULTS = {
    # Naming Defaults
    "SRC_NAME": 'VPN-SOURCE-LOCAL',
    "INSIDE_IFACE": 'Inside',
    "OUTSIDE_IFACE": 'Outside',
    "CRYPTO_MAP_NAME": 'outside_map',

    # IKE/IPsec Parameters (IKEv2)
    "IKEV2_P1_ENCRYPT": "aes-256",
    "IKEV2_P1_INTEGRITY": "sha256",
    "IKEV2_P1_GROUP": 14,
    "IKEV2_P1_PRF": "sha256",
    "IKEV2_P1_LIFETIME": 86400,

    "IKEV2_P2_PROPOSAL_NAME": "AES256-SHA256",
    "IKEV2_P2_ENCRYPT": "aes-256",
    "IKEV2_P2_INTEGRITY": "sha-256",
    "IKEV2_P2_LIFETIME": 28800, # Crypto map lifetime

    # Validation Constants
    "MIN_PSK_LENGTH": 8,
    "MAX_CMS_VALUE": 65535,
    "MIN_CMS_VALUE": 1,
}

# Embedded IKEv2 crypto config (printed when requested)
IKEV2_CRYPTO = f'''Phase1
crypto ikev2 policy 1
 encryption {TUNNEL_DEFAULTS["IKEV2_P1_ENCRYPT"]}
 integrity {TUNNEL_DEFAULTS["IKEV2_P1_INTEGRITY"]}
 group {TUNNEL_DEFAULTS["IKEV2_P1_GROUP"]}
 prf {TUNNEL_DEFAULTS["IKEV2_P1_PRF"]}
 lifetime seconds {TUNNEL_DEFAULTS["IKEV2_P1_LIFETIME"]}

Phase2
crypto ipsec ikev2 ipsec-proposal {TUNNEL_DEFAULTS["IKEV2_P2_PROPOSAL_NAME"]}
 protocol esp encryption {TUNNEL_DEFAULTS["IKEV2_P2_ENCRYPT"]}
 protocol esp integrity {TUNNEL_DEFAULTS["IKEV2_P2_INTEGRITY"]}
'''

# ----------------------------------------------------------------------
# --- VALIDATION AND HELPER FUNCTIONS ---
# ----------------------------------------------------------------------

def _validate_config_name(name: str, field_name: str):
    """Checks if a configuration name contains invalid characters."""
    # Enforces alphanumeric characters, hyphens, or underscores. No spaces or most punctuation.
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError(f"Invalid characters detected in {field_name} ('{name}'). Names must be alphanumeric and may contain hyphens (-) or underscores (_). No spaces allowed.")


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
        print(f"Error: No valid {entry_type} networks were provided.", file=sys.stderr)
        sys.exit(2)
        
    return valid, invalid


def _validate_peer_ip(peer_input: str, allow_private: bool) -> str:
    """Validates the peer IP address for public IPv4 /32."""
    if not peer_input:
        raise ValueError("Peer IP address is required.")

    addr = None
    peer_reason = None
    
    try:
        if "/" in peer_input:
            peer_net = ipaddress.ip_network(peer_input, strict=False)
            if peer_net.version != 4 or peer_net.prefixlen != 32 or peer_net.num_addresses != 1:
                peer_reason = 'network prefix is not /32 or invalid format'
            else:
                addr = peer_net.network_address
        else:
            candidate = ipaddress.ip_address(peer_input)
            if candidate.version != 4:
                peer_reason = 'not an IPv4 address'
            else:
                addr = candidate

        if addr is not None and peer_reason is None:
            if allow_private or getattr(addr, 'is_global', False):
                return str(addr)
            else:
                peer_reason = 'address is not a public/global IPv4 address'
        
    except ValueError:
        peer_reason = 'invalid IP format'

    raise ValueError(f"Invalid peer IP ({peer_input}): {peer_reason}")


# ----------------------------------------------------------------------
# --- CONFIGURATION GENERATION FUNCTIONS ---
# ----------------------------------------------------------------------

def _format_object_group(group_name: str, networks: List[str]) -> str:
    """Generates the Cisco ASA object-group network configuration block."""
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
    """Generates the VPN-specific access-list statement."""
    return f"access-list {acl_name} extended permit ip object-group {src_name} object-group {dst_name}"


def _generate_nat_statement(nat_inside: str, nat_outside: str, src_name: str, dst_name: str) -> str:
    """Generates the NAT Exemption statement (no-nat for VPN traffic)."""
    return (
        f"nat ({nat_inside},{nat_outside}) source static {src_name} {src_name} "
        f"destination static {dst_name} {dst_name} no-proxy-arp route-lookup"
    )


def _generate_crypto_map(crypto_map_name: str, crypto_map_seq: int, acl_name: str, peer_ip: str) -> str:
    """Generates the crypto map lines."""
    proposal_name = TUNNEL_DEFAULTS['IKEV2_P2_PROPOSAL_NAME']
    lifetime = TUNNEL_DEFAULTS['IKEV2_P2_LIFETIME']
    
    lines = [
        f"crypto map {crypto_map_name} {crypto_map_seq} match address {acl_name}",
        f"crypto map {crypto_map_name} {crypto_map_seq} set peer {peer_ip}",
        f"crypto map {crypto_map_name} {crypto_map_seq} set ikev2 ipsec-proposal {proposal_name}",
        f"crypto map {crypto_map_name} {crypto_map_seq} set security-association lifetime seconds {lifetime}"
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


# ----------------------------------------------------------------------
# --- CORE LOGIC FUNCTIONS ---
# ----------------------------------------------------------------------

def print_custom_help():
    """
    Prints the manually formatted, categorized help section.
    References to the -c flag have been removed.
    """
    # Pull defaults from TUNNEL_DEFAULTS
    min_cms = TUNNEL_DEFAULTS["MIN_CMS_VALUE"]
    max_cms = TUNNEL_DEFAULTS["MAX_CMS_VALUE"]
    min_psk = TUNNEL_DEFAULTS["MIN_PSK_LENGTH"]
    src_name = TUNNEL_DEFAULTS["SRC_NAME"]
    inside_iface = TUNNEL_DEFAULTS["INSIDE_IFACE"]
    outside_iface = TUNNEL_DEFAULTS["OUTSIDE_IFACE"]
    crypto_map_name = TUNNEL_DEFAULTS["CRYPTO_MAP_NAME"]

    formatted_help_content = f"""\
REQUIRED ARGUMENTS (for non-interactive mode ):
  Short   Long                    Description
  ------  ---------------------   ------------------------------------------
  -s      --sources               Comma-separated source networks (CIDR or subnet mask) [REQUIRED]
  -d      --destinations          Comma-separated destination networks [REQUIRED]
  -dn     --dst-name              Destination object-group name [REQUIRED]
  -cms    --crypto-map-seq        Crypto map sequence number (integer {min_cms}-{max_cms}) [REQUIRED]
  -psk    --pre-shared-key        Pre-shared key (min {min_psk} chars) for tunnel-group [REQUIRED]
  -p      --peer                  Peer IP (IPv4 host or /32) [REQUIRED]

OPTIONAL ARGUMENTS WITH DEFAULTS:
  Short   Long                    Description
  ------  ---------------------   ------------------------------------------
  -sn     --src-name              Source object-group name [default: {src_name}]
  -ni     --nat-inside            NAT Inside interface name [default: {inside_iface}]
  -no     --nat-outside           NAT Outside interface name [default: {outside_iface}]
  -cmn    --crypto-map-name       Crypto map name [default: {crypto_map_name}]

OPTIONAL OUTPUT/CONTROL ARGUMENTS:
  Short   Long                    Description
  ------  ---------------------   ------------------------------------------
  -o      --output                File path to save object-groups
  -ap     --allow-private-peer    Allow private/non-global peer addresses
  -pc     --print-crypto          Print the embedded IKEv2 crypto config

USAGE EXAMPLES:
  Interactive mode (prompts for values):
    python asa_vpn_creator.py

  Non-interactive mode (requires all REQUIRED arguments):
    python asa_vpn_creator.py -s 10.0.0.0/24 -d 192.168.0.0/24 -p 203.0.113.1 \\
      -dn VPN-DESTINATION-REMOTE -cms 5 -psk "SecureKey123!"

  Non-interactive mode with custom NAT and crypto map:
    python asa_vpn_creator.py -s 10.0.0.0/24 -d 192.168.0.0/24 -p 203.0.113.1 \\
      -dn VPN-DESTINATION-REMOTE -cms 5 -psk "SecureKey123!" \\
      -ni LAN -no WAN -cmn site1_vpn -o config.txt
"""
    print(formatted_help_content)


def get_required_inputs(cli_args: argparse.Namespace) -> Dict[str, Any]:
    """
    Handles all input retrieval (CLI or interactive prompt).
    Infers non-interactive mode if all required CLI arguments are present.
    Incorporates immediate validation and reprompting for required inputs.
    """
    data = {}
    
    # Validation Constants
    MIN_PSK_LENGTH = TUNNEL_DEFAULTS["MIN_PSK_LENGTH"]
    MAX_CMS_VALUE = TUNNEL_DEFAULTS["MAX_CMS_VALUE"]
    MIN_CMS_VALUE = TUNNEL_DEFAULTS["MIN_CMS_VALUE"]
    
    # Naming Defaults
    DEFAULT_SRC_NAME = TUNNEL_DEFAULTS["SRC_NAME"]
    DEFAULT_INSIDE_IFACE = TUNNEL_DEFAULTS["INSIDE_IFACE"]
    DEFAULT_OUTSIDE_IFACE = TUNNEL_DEFAULTS["OUTSIDE_IFACE"]
    DEFAULT_CRYPTO_MAP_NAME = TUNNEL_DEFAULTS["CRYPTO_MAP_NAME"]

    # 1. Determine CLI presence for all required arguments
    required_cli_args = [
        cli_args.sources, cli_args.destinations, cli_args.peer, 
        cli_args.dst_name, cli_args.crypto_map_seq, cli_args.pre_shared_key
    ]
    
    # Flag 1: Non-interactive if ALL required arguments were provided on CLI
    is_non_interactive = all(arg is not None for arg in required_cli_args)
    data['is_non_interactive'] = is_non_interactive
    
    # Flag 2: Full interactive if NONE of the required arguments were provided on CLI
    is_full_interactive_run = not any(arg is not None for arg in required_cli_args)


    # --- CLI Input Pre-Validation for Config Names and Sequence/Key ---
    
    # Optional Args Pre-Validation (must pass or fail early)
    if cli_args.nat_inside:
        _validate_config_name(cli_args.nat_inside, "NAT Inside interface name")
    if cli_args.nat_outside:
        _validate_config_name(cli_args.nat_outside, "NAT Outside interface name")
    if cli_args.crypto_map_name:
        _validate_config_name(cli_args.crypto_map_name, "Crypto map name")
    
    # Required Args Pre-Validation
    if cli_args.crypto_map_seq is not None:
        try:
            val = int(cli_args.crypto_map_seq)
            if not (MIN_CMS_VALUE <= val <= MAX_CMS_VALUE):
                raise ValueError(f"Sequence number must be between {MIN_CMS_VALUE} and {MAX_CMS_VALUE}.")
        except ValueError as e:
            raise ValueError(f"Crypto map sequence error: {e}")

    if cli_args.pre_shared_key and len(cli_args.pre_shared_key) < MIN_PSK_LENGTH:
        raise ValueError(f"Pre-shared key must be at least {MIN_PSK_LENGTH} characters long.")

    
    # --- Input Handling for REQUIRED Arguments (Validation loops ensure we break on valid input) ---
    
    # Source Networks
    source_input = cli_args.sources
    if not source_input:
        while True:
            source_input = input("Enter source network(s) (CIDR or subnet mask, comma-separated): ").strip()
            if source_input:
                break
            print("Source networks are required.")
    data['sources'] = [entry.strip() for entry in source_input.split(",") if entry.strip()]

    # Destination Networks
    dest_input = cli_args.destinations
    if not dest_input:
        while True:
            dest_input = input("\nEnter destination networks (comma-separated): ").strip()
            if dest_input:
                break
            print("Destination networks are required.")
    data['destinations'] = [entry.strip() for entry in dest_input.split(",") if entry.strip()]

    # Peer IP
    peer_input = str(cli_args.peer).strip() if cli_args.peer is not None else None
    if not peer_input:
        while True:
            peer_input = input("\nEnter peer IP address (IPv4 host or IPv4/32): ").strip()
            if peer_input:
                break
            print("Peer IP is required.")
    data['peer_input'] = peer_input

    # Destination Name Input 
    dst_name_input = cli_args.dst_name
    if not dst_name_input:
        while True:
            dst_name_input = input("Enter destination name (will be formatted as VPN-{name}-REMOTE): ").strip()
            if not dst_name_input:
                print("Destination name is required. Please enter a name.")
                continue
            try:
                # Immediate name validation
                _validate_config_name(dst_name_input, "Destination name")
                break
            except ValueError as e:
                print(f"Invalid input: {e}")
                
    # Validate destination name even if it came from CLI
    _validate_config_name(dst_name_input, "Destination name")
    data['dst_name_input'] = dst_name_input.upper()

    # Crypto Map Sequence
    data['crypto_map_seq'] = None
    if cli_args.crypto_map_seq is not None:
        data['crypto_map_seq'] = int(cli_args.crypto_map_seq) 
    else:
        while True:
            seq_input = input(f"Enter crypto map sequence number (required, integer {MIN_CMS_VALUE}-{MAX_CMS_VALUE}): ").strip()
            try:
                # Immediate integer and range validation
                val = int(seq_input)
                if not (MIN_CMS_VALUE <= val <= MAX_CMS_VALUE):
                    raise ValueError(f"Sequence number must be between {MIN_CMS_VALUE} and {MAX_CMS_VALUE}.")
                data['crypto_map_seq'] = val
                break
            except ValueError as e:
                print(f"Invalid input: {e}")
                
    # Pre-shared Key
    data['pre_shared_key'] = cli_args.pre_shared_key
    if not data['pre_shared_key']:
        while True:
            data['pre_shared_key'] = input(f"\nEnter pre-shared key (required, min {MIN_PSK_LENGTH} characters): ").strip()
            if not data['pre_shared_key']:
                print("Pre-shared key is required. Please enter a value.")
            elif len(data['pre_shared_key']) < MIN_PSK_LENGTH:
                print(f"Pre-shared key must be at least {MIN_PSK_LENGTH} characters long.")
            else:
                break
            
    
    # --- Input Handling for OPTIONAL Arguments with Defaults (Uses is_full_interactive_run flag) ---

    # Source Object-Group Name
    src_name = cli_args.src_name
    if src_name:
        src_name = src_name 
    elif is_full_interactive_run:
        # FULL Interactive mode: Prompt user for optional defaults
        while True:
            src_name = input(f"Enter source object-group name [{DEFAULT_SRC_NAME}]: ").strip() or DEFAULT_SRC_NAME
            try:
                _validate_config_name(src_name, "Source name")
                break
            except ValueError as e:
                print(f"Invalid input: {e}")
    else:
        # Hybrid or Pure Non-interactive mode: use default silently
        src_name = DEFAULT_SRC_NAME
        
    data['src_name'] = src_name
    
    # NAT Inside Interface Name
    if cli_args.nat_inside:
        data['nat_inside'] = cli_args.nat_inside
    elif is_full_interactive_run:
        # FULL Interactive mode: Prompt user for optional defaults
        while True:
            nat_input = input(f"\nEnter NAT Inside interface name [{DEFAULT_INSIDE_IFACE}]: ").strip() or DEFAULT_INSIDE_IFACE
            try:
                _validate_config_name(nat_input, "NAT Inside interface name")
                data['nat_inside'] = nat_input
                break
            except ValueError as e:
                print(f"Invalid input: {e}")
    else:
        # Hybrid or Pure Non-interactive mode: use default silently
        data['nat_inside'] = DEFAULT_INSIDE_IFACE

    # NAT Outside Interface Name
    if cli_args.nat_outside:
        data['nat_outside'] = cli_args.nat_outside
    elif is_full_interactive_run:
        # FULL Interactive mode: Prompt user for optional defaults
        while True:
            nat_input = input(f"Enter NAT Outside interface name [{DEFAULT_OUTSIDE_IFACE}]: ").strip() or DEFAULT_OUTSIDE_IFACE
            try:
                _validate_config_name(nat_input, "NAT Outside interface name")
                data['nat_outside'] = nat_input
                break
            except ValueError as e:
                print(f"Invalid input: {e}")
    else:
        # Hybrid or Pure Non-interactive mode: use default silently
        data['nat_outside'] = DEFAULT_OUTSIDE_IFACE

    # Crypto Map Name
    if cli_args.crypto_map_name:
        data['crypto_map_name'] = cli_args.crypto_map_name
    elif is_full_interactive_run:
        # FULL Interactive mode: Prompt user for optional defaults
        while True:
            crypto_input = input(f"\nEnter crypto map name [{DEFAULT_CRYPTO_MAP_NAME}]: ").strip() or DEFAULT_CRYPTO_MAP_NAME
            try:
                _validate_config_name(crypto_input, "Crypto map name")
                data['crypto_map_name'] = crypto_input
                break
            except ValueError as e:
                print(f"Invalid input: {e}")
    else:
        # Hybrid or Pure Non-interactive mode: use default silently
        data['crypto_map_name'] = DEFAULT_CRYPTO_MAP_NAME
            
    # Final validation on optional names (must be done outside of interactive block for consistency)
    _validate_config_name(data['src_name'], "Source name")
    _validate_config_name(data['nat_inside'], "NAT Inside interface name")
    _validate_config_name(data['nat_outside'], "NAT Outside interface name")
    _validate_config_name(data['crypto_map_name'], "Crypto map name")
    
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
    
    return full_config_string, src_block + "\n\n" + dst_block, dst_name


def save_config_to_file(file_path: str, config_content: str):
    """Saves the configuration content to a file using pathlib, raising OSError on failure."""
    try:
        Path(file_path).write_text(config_content + "\n")
        print(f"\nSaved full configuration to: {file_path}")
    except OSError as e:
        # Re-raise with detailed context for the caller to handle
        raise OSError(f"Failed to write to '{file_path}'. Reason: {e}")


# ----------------------------------------------------------------------
# --- ARGUMENT PARSING ---
# ----------------------------------------------------------------------

def _build_arg_parser():
    # Pull defaults for help text
    inside_iface = TUNNEL_DEFAULTS["INSIDE_IFACE"]
    outside_iface = TUNNEL_DEFAULTS["OUTSIDE_IFACE"]
    crypto_map_name = TUNNEL_DEFAULTS["CRYPTO_MAP_NAME"]
    src_name = TUNNEL_DEFAULTS["SRC_NAME"]

    p = argparse.ArgumentParser(
        description='Create IPSec VPN configuration for Cisco ASA (Refactored)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False  # Disabled to use custom help
    )
    
    # Manually defined help argument
    p.add_argument('--help', '-h', 
                   dest='custom_help', 
                   action='store_true', 
                   help='show this help message and exit')
                   
    p.add_argument('--sources', '-s', help='Comma-separated source networks (CIDR or subnet mask)')
    p.add_argument('--destinations', '-d', help='Comma-separated destination networks')
    p.add_argument('--peer', '-p', help='Peer IP (IPv4 host or /32)')
    p.add_argument('--src-name', '-sn', help=f'Source object-group name')
    p.add_argument('--dst-name', '-dn', help='Destination object-group name')
    p.add_argument('--output', '-o', help='File path to save configuration')
    p.add_argument('--allow-private-peer', '-ap', dest='allow_private_peer', action='store_true', help='Allow private/non-global peer addresses')
    p.add_argument('--print-crypto', '-pc', dest='print_crypto', action='store_true', help='Print the embedded IKEv2 crypto config included in this script')
    p.add_argument('--nat-inside', '-ni', dest='nat_inside', help=f'NAT Inside interface name (default: {inside_iface})')
    p.add_argument('--nat-outside', '-no', dest='nat_outside', help=f'NAT Outside interface name (default: {outside_iface})')
    p.add_argument('--crypto-map-name', '-cmn', dest='crypto_map_name', help=f'Crypto map name (default: {crypto_map_name})')
    p.add_argument('--crypto-map-seq', '-cms', dest='crypto_map_seq', help='Crypto map sequence number (required for crypto map generation)')
    p.add_argument('--pre-shared-key', '-psk', dest='pre_shared_key', help='Pre-shared key for tunnel-group (required in non-interactive mode)')
    return p


# ----------------------------------------------------------------------
# --- MAIN EXECUTION BLOCK ---
# ----------------------------------------------------------------------

if __name__ == "__main__":
    parser = _build_arg_parser()
    args = parser.parse_args()

    # Check for custom help argument first
    if args.custom_help:
        print_custom_help()
        sys.exit(0)
    
    try:
        # Step 1: Get all inputs (CLI or Interactive)
        config_data = get_required_inputs(args)
        
        # Determine non-interactive status for final flow control
        is_non_interactive = config_data.get('is_non_interactive', False) 
        
        # Step 2: Perform Validation 
        config_data = validate_and_process_inputs(config_data, args)
        
        # Step 3: Generate Configuration
        full_config, _, _ = generate_full_config(config_data)

        # Step 4: Display Output
        print("\n" + "="*50)
        print("GENERATED CISCO ASA VPN CONFIGURATION")
        print("="*50)
        print(full_config)
        print("\n" + "="*50)

        # Print Crypto Config if requested (Only print if non-interactive mode and no specific output file was specified)
        if args.print_crypto or (is_non_interactive and not args.output):
            print('\n--- Recommended IKEv2 Crypto Config ---\n')
            print(IKEV2_CRYPTO.rstrip())

        # Step 5: Handle Saving
        save_path = args.output
        
        if save_path:
            # Scenario 1: Path provided via CLI. Attempt to save. If it fails, the top-level try/except will catch it and exit.
            save_config_to_file(save_path, full_config)
        
        elif not is_non_interactive:
            # Scenario 2: Interactive/Hybrid mode without CLI output path. Loop until success or user skips.
            while True:
                save_path_prompt = input("\nSave full configuration to file? (enter path or leave blank to skip): ").strip()
                
                if not save_path_prompt:
                    print("Skipping file save.")
                    break # User chose to skip saving
                
                try:
                    # Use the common saving function
                    save_config_to_file(save_path_prompt, full_config)
                    break # Success
                except OSError as e:
                    # Catch and report the file save error, then loop to reprompt
                    # Note: The save_config_to_file already formats the error message
                    print(f"\n❌ FILE SAVE ERROR: {e}. Please try a different path.", file=sys.stderr)
                    continue
        # If is_non_interactive is True and args.output is None, saving is skipped silently, which is correct non-interactive behavior.

    except (ValueError, OSError) as e:
        # Catch errors from validation functions (ValueError) and file I/O (OSError)
        print(f"\n❌ FATAL ERROR: {e}", file=sys.stderr)
        sys.exit(2)