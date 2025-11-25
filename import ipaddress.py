import argparse
import ipaddress
import sys

# Embedded IKEv2 crypto config (printed when requested)
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


def validate_networks(cli=None):
    # Validate required arguments in non-interactive mode upfront
    if cli and getattr(cli, 'create_object_groups', False):
        missing_args = []
        if not getattr(cli, 'destinations', None):
            missing_args.append('--destinations')
        if not getattr(cli, 'dst_name', None):
            missing_args.append('--dst-name')
        if not getattr(cli, 'acl_dest', None):
            missing_args.append('--acl-dest')
        if not getattr(cli, 'crypto_map_seq', None):
            missing_args.append('--crypto-map-seq')
        if missing_args:
            print(f"Error: The following required arguments are missing in non-interactive mode: {', '.join(missing_args)}")
            sys.exit(2)
    
    # Get source networks (allow comma-separated values)
    if cli and getattr(cli, 'sources', None):
        source_input = cli.sources.strip()
    else:
        source_input = input("Enter source network(s) (CIDR or subnet mask format, comma-separated): ").strip()
    sources = [entry.strip() for entry in source_input.split(",") if entry.strip()]

    valid_sources = []
    invalid_sources = []

    for entry in sources:
        try:
            src_network = ipaddress.ip_network(entry, strict=False)
            valid_sources.append(str(src_network))
        except ValueError:
            invalid_sources.append(entry)

    # Get destination networks
    if cli and getattr(cli, 'destinations', None):
        dest_input = cli.destinations.strip()
    else:
        dest_input = input("\nEnter destination networks (comma-separated): ").strip()
    destinations = [entry.strip() for entry in dest_input.split(",") if entry.strip()]

    valid_destinations = []
    invalid_destinations = []

    for entry in destinations:
        try:
            dest_network = ipaddress.ip_network(entry, strict=False)
            valid_destinations.append(str(dest_network))
        except ValueError:
            invalid_destinations.append(entry)

    # Get peer IP address (single host) and ensure it's IPv4 /32 and public
    if cli and getattr(cli, 'peer', None) is not None:
        peer_input = str(cli.peer).strip()
    else:
        peer_input = input("\nEnter peer IP address (IPv4 host or IPv4/32, e.g. 198.51.100.1 or 198.51.100.1/32): ").strip()
    peer_valid = False
    peer_value = None
    peer_reason = None
    if peer_input:
        addr = None
        try:
            if "/" in peer_input:
                peer_net = ipaddress.ip_network(peer_input, strict=False)
                # must be IPv4 and a /32 host network
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
                # require public/global IPv4 unless CLI allows private peers
                allow_private = bool(cli and getattr(cli, 'allow_private_peer', False))
                if allow_private:
                    peer_valid = True
                    peer_value = str(addr)
                else:
                    if getattr(addr, 'is_global', False):
                        peer_valid = True
                        peer_value = str(addr)
                    else:
                        # determine specific non-public reason
                        if getattr(addr, 'is_private', False):
                            peer_reason = 'address is private'
                        elif getattr(addr, 'is_loopback', False):
                            peer_reason = 'address is loopback'
                        elif getattr(addr, 'is_link_local', False):
                            peer_reason = 'address is link-local'
                        elif getattr(addr, 'is_multicast', False):
                            peer_reason = 'address is multicast'
                        elif getattr(addr, 'is_reserved', False):
                            peer_reason = 'address is reserved'
                        else:
                            peer_reason = 'address is not a public/global IPv4 address'
        except ValueError:
            peer_reason = 'invalid IP format'

    # Display peer result
    if peer_valid:
        print(f"\n✅ Valid public IPv4 peer (/32): {peer_value}")
    else:
        reason_text = f" - {peer_reason}" if peer_reason else ''
        print(f"\n❌ Invalid peer IP (requires public IPv4 /32): {peer_input}{reason_text}")

    # Display results for sources
    print("\n✅ Valid source networks:")
    for net in valid_sources:
        print(f" - {net}")

    if invalid_sources:
        print("\n❌ Invalid source entries:")
        for net in invalid_sources:
            print(f" - {net}")

    # Display results for destinations
    print("\n✅ Valid destination networks:")
    for net in valid_destinations:
        print(f" - {net}")

    if invalid_destinations:
        print("\n❌ Invalid destination entries:")
        for net in invalid_destinations:
            print(f" - {net}")

    # Offer to create Cisco IOS object-group output
    if cli and getattr(cli, 'create_object_groups', False):
        create_og = 'y'
    else:
        create_og = input("\nCreate Cisco object-group output from valid networks? (y/N): ").strip().lower()
    if create_og == 'y':
        # default names
        default_src_name = 'VPN-SOURCE-LOCAL'
        default_dst_name = 'VPN-DESTINATION-REMOTE'
        if cli and getattr(cli, 'src_name', None):
            src_name = cli.src_name
        elif cli and getattr(cli, 'create_object_groups', False):
            src_name = default_src_name
        else:
            src_name = input(f"Enter source object-group name [{default_src_name}]: ").strip() or default_src_name

        # Uppercase object-group names for consistency
        src_name = src_name.upper()

        if cli and getattr(cli, 'dst_name', None):
            dst_name = cli.dst_name
        else:
            # Interactive: prompt until a non-empty destination name is supplied
            while True:
                dst_name = input("Enter destination object-group name (required): ").strip()
                if dst_name:
                    break
                print("Destination name is required. Please enter a name.")

        # Uppercase destination object-group name
        dst_name = dst_name.upper()

        def format_object_group(group_name, networks):
            lines = []
            lines.append(f"object-group network {group_name}")
            for n in networks:
                try:
                    net = ipaddress.ip_network(n, strict=False)
                    addr = str(net.network_address)
                    # convert to Cisco IOS network-object format for IPv4
                    if net.version == 4:
                        if net.prefixlen == 32:
                            # prefer the 'host' form for single-address networks
                            lines.append(f" network-object host {addr}")
                        else:
                            netmask = str(net.netmask)
                            lines.append(f" network-object {addr} {netmask}")
                    else:
                        # For IPv6, use the CIDR form as a comment (IOS object-groups are IPv4-focused)
                        lines.append(f" ! skipping IPv6 entry: {n}")
                        continue
                except ValueError:
                    lines.append(f" ! invalid entry skipped: {n}")
            return "\n".join(lines)

        src_block = format_object_group(src_name, valid_sources)
        dst_block = format_object_group(dst_name, valid_destinations)

        print("\n--- Generated object-groups ---\n")
        print(src_block)
        print()
        print(dst_block)
        # Determine ACL destination label and build the ACL name (TO-<dest>-VPN)
        import re
        # allow letters (any case), numbers and hyphens; will uppercase when building ACL name
        label_pattern = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$')
        if cli and getattr(cli, 'acl_dest', None):
            # normalize spaces to single hyphens, strip surrounding hyphens
            acl_dest = re.sub(r"\s+", '-', cli.acl_dest.strip())
            acl_dest = acl_dest.strip('-')
            if not label_pattern.match(acl_dest):
                print("Error: --acl-dest must contain letters, numbers or hyphens (e.g. kearney or lincoln-north)")
                sys.exit(2)
        else:
            # Interactive: prompt until a valid destination label is supplied
            while True:
                # normalize spaces to hyphens for user-entered labels too
                raw = input("Enter ACL destination label (e.g., kearney or lincoln-north): ").strip()
                acl_dest = re.sub(r"\s+", '-', raw)
                acl_dest = acl_dest.strip('-')
                if not acl_dest:
                    print("Destination label is required. Please enter a short label (e.g., kearney).")
                    continue
                if not label_pattern.match(acl_dest):
                    print("Invalid label. Use lowercase letters, numbers and hyphens only (e.g. lincoln-north).")
                    continue
                break

        # Build ACL name in uppercase (e.g. TO-KEARNEY-VPN)
        acl_name = f"TO-{acl_dest.upper()}-VPN"
        acl_line = f"access-list {acl_name} extended permit ip object-group {src_name} object-group {dst_name}"
        print("\n--- Access-list ---\n")
        print(acl_line)

        # Get NAT interface names (Inside and Outside)
        default_inside = 'Inside'
        default_outside = 'Outside'
        if cli and getattr(cli, 'nat_inside', None):
            nat_inside = cli.nat_inside
        elif cli and getattr(cli, 'create_object_groups', False):
            nat_inside = default_inside
        else:
            nat_inside = input(f"\nEnter NAT Inside interface name [{default_inside}]: ").strip() or default_inside

        if cli and getattr(cli, 'nat_outside', None):
            nat_outside = cli.nat_outside
        elif cli and getattr(cli, 'create_object_groups', False):
            nat_outside = default_outside
        else:
            nat_outside = input(f"Enter NAT Outside interface name [{default_outside}]: ").strip() or default_outside

        # Generate NAT statement
        nat_line = f"nat ({nat_inside},{nat_outside}) source static {src_name} {src_name} destination static {dst_name} {dst_name}  no-proxy-arp route-lookup"
        print("\n--- NAT Statement ---\n")
        print(nat_line)

        # Get crypto map configuration
        default_crypto_map_name = 'outside_map'
        if cli and getattr(cli, 'crypto_map_name', None):
            crypto_map_name = cli.crypto_map_name
        elif cli and getattr(cli, 'create_object_groups', False):
            crypto_map_name = default_crypto_map_name
        else:
            crypto_map_name = input(f"\nEnter crypto map name [{default_crypto_map_name}]: ").strip() or default_crypto_map_name

        # Crypto map sequence number is required
        crypto_map_seq = None
        if cli and getattr(cli, 'crypto_map_seq', None) is not None:
            try:
                crypto_map_seq = int(cli.crypto_map_seq)
            except ValueError:
                print("Error: --crypto-map-seq must be a valid integer")
                sys.exit(2)
        else:
            while crypto_map_seq is None:
                seq_input = input("Enter crypto map sequence number (required, integer): ").strip()
                try:
                    crypto_map_seq = int(seq_input)
                except ValueError:
                    print("Invalid input. Please enter a valid integer.")

        # Generate crypto map lines
        crypto_map_lines = [
            f"crypto map {crypto_map_name} {crypto_map_seq} match address {acl_name}",
            f"crypto map {crypto_map_name} {crypto_map_seq} set peer {peer_value}",
            f"crypto map {crypto_map_name} {crypto_map_seq} set ikev2 ipsec-proposal AES256-SHA256",
            f"crypto map {crypto_map_name} {crypto_map_seq} set security-association lifetime seconds 28800"
        ]
        crypto_map_output = "\n".join(crypto_map_lines)
        print("\n--- Crypto Map ---\n")
        print(crypto_map_output)

        # Print crypto block if requested or if create_object_groups is used and no explicit flag
        crypto_requested = bool((cli and getattr(cli, 'print_crypto', False))) or bool(cli and getattr(cli, 'create_object_groups', False) and not getattr(cli, 'output', None))
        if crypto_requested:
            # Print embedded crypto constant
            if IKEV2_CRYPTO.strip():
                print('\n--- Recommended IKEv2 crypto config ---\n')
                print(IKEV2_CRYPTO.rstrip())

        # Optionally write to a file. In non-interactive mode (--create-object-groups)
        # and when no --output is provided, print to stdout and do NOT prompt to save.
        if cli and getattr(cli, 'output', None):
            save = cli.output
        elif cli and getattr(cli, 'create_object_groups', False):
            # non-interactive: don't prompt to save, output already printed to stdout
            save = None
        else:
            save = input("\nSave output to file? (enter path or leave blank to skip): ").strip()

        if save:
            mode = 'w'
            try:
                with open(save, mode) as f:
                    # include ACL line, NAT statement, and crypto map if present
                    if acl_name:
                        f.write(src_block + "\n\n" + dst_block + "\n\n" + acl_line + "\n\n" + nat_line + "\n\n" + crypto_map_output + "\n")
                    else:
                        f.write(src_block + "\n\n" + dst_block + "\n")
                print(f"\nSaved object-groups to: {save}")
            except OSError as e:
                print(f"\nFailed to write file: {e}")

def _build_arg_parser():
    p = argparse.ArgumentParser(description='Validate networks and optionally create Cisco object-groups')
    p.add_argument('--sources', help='Comma-separated source networks (CIDR or subnet mask)')
    p.add_argument('--destinations', help='Comma-separated destination networks')
    p.add_argument('--peer', help='Peer IP (IPv4 host or /32)')
    p.add_argument('--create-object-groups', dest='create_object_groups', action='store_true', help='Create object-group output without interactive prompt')
    p.add_argument('--src-name', help='Source object-group name')
    p.add_argument('--dst-name', help='Destination object-group name')
    p.add_argument('--output', help='File path to save object-groups')
    p.add_argument('--allow-private-peer', dest='allow_private_peer', action='store_true', help='Allow private/non-global peer addresses')
    p.add_argument('--print-crypto', dest='print_crypto', action='store_true', help='Print the embedded IKEv2 crypto config included in this script')
    p.add_argument('--acl-dest', dest='acl_dest', help='Short destination label used to build ACL name (script builds TO-<dest>-VPN)')
    p.add_argument('--nat-inside', dest='nat_inside', help='NAT Inside interface name (default: Inside)')
    p.add_argument('--nat-outside', dest='nat_outside', help='NAT Outside interface name (default: Outside)')
    p.add_argument('--crypto-map-name', dest='crypto_map_name', help='Crypto map name (default: outside_map)')
    p.add_argument('--crypto-map-seq', dest='crypto_map_seq', help='Crypto map sequence number (required for crypto map generation)')
    return p


if __name__ == "__main__":
    parser = _build_arg_parser()
    args = parser.parse_args()
    validate_networks(cli=args)