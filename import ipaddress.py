import argparse
import ipaddress

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

        if cli and getattr(cli, 'dst_name', None):
            dst_name = cli.dst_name
        elif cli and getattr(cli, 'create_object_groups', False):
            dst_name = default_dst_name
        else:
            dst_name = input(f"Enter destination object-group name [{default_dst_name}]: ").strip() or default_dst_name

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
            mode = 'a' if (cli and getattr(cli, 'append', False)) else 'w'
            try:
                with open(save, mode) as f:
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
    p.add_argument('--append', action='store_true', help='Append to output file instead of overwriting')
    p.add_argument('--allow-private-peer', dest='allow_private_peer', action='store_true', help='Allow private/non-global peer addresses')
    p.add_argument('--print-crypto', dest='print_crypto', action='store_true', help='Print IKEv2 crypto config (from IKEV2 Crypto.txt by default)')
    return p


if __name__ == "__main__":
    parser = _build_arg_parser()
    args = parser.parse_args()
    validate_networks(cli=args)