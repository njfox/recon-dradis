#!/usr/bin/env python

import ipaddress
import getopt
import sys
import json
import sublist3r
import dns.resolver
from pydradis.pydradis import Pydradis

USAGE = "Usage: %s [-d <domain>] [-f <domain file>] [-s <scope file>] -p '<project name>'"

def parse_cli_options(argv):
    domains = []
    domain_filename = ""
    scope_subnets = []
    scope_filename = ""
    project_name = ""

    try:
        opts, args = getopt.getopt(argv[1:],"hd:f:s:p:",["help","domain=","domain-file=","scope-file=","project-name="])
    except getopt.GetoptError:
        print "[+] Error: Invalid options specified."
        print USAGE % argv[0]
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print USAGE % argv[0]
            sys.exit()
        elif opt in ("-d", "--domain"):
            domains.append(arg)
        elif opt in ("-f", "--domain-file"):
            domain_filename = arg
        elif opt in ("-s", "--scope-file"):
            scope_filename = arg
        elif opt in ("-p", "--project-name"):
            project_name = arg

    if domain_filename:
        try:
            f = open(domain_filename, "r")
            for domain in f:
                domains.append(domain.strip())
            f.close()
        except IOError:
            print "[+] Error: Could not open domain file"
            sys.exit(2)

    if scope_filename:
        try:
            f = open(scope_filename, "r")
            for line in f:
                network = ipaddress.ip_network(line.strip().decode())
                scope_subnets.append(network)
            f.close()
            if len(scope_subnets) == 0:
                print "[+] Error: Could not parse IP ranges in scope file."
                sys.exit(2)
        except IOError:
            print "[+] Error: Could not open scope file"
            sys.exit(2)

    if len(domains) == 0:
        print "[+] Error: Could not parse target domains"
        sys.exit(2)
    if not project_name:
        print "[+] Error: Invalid project name"
        sys.exit(2)
    
    return (domains, scope_subnets, project_name)


def init_dradis():
    try:
        config = open("dradis_config.json", "r")
        info = json.load(config)
    except IOError:
        print "[+] Error: Error opening Dradis configuration file."
        sys.exit(2)

    config.close()
    api_key = info["api_key"]
    if not api_key:
        print "[+] Error: dradis_config.json must include a valid API key."
        sys.exit(2)

    dradis_url = info["dradis_url"]
    if not dradis_url:
        print "[+] Error: dradis_config.json must include a valid Dradis URL."
        sys.exit(2)
    
    debug = info["debug"]
    verify = info["verify"]

    return Pydradis(api_key, dradis_url, debug, verify)


def find_project_id(pd, name):
    project_id = pd.find_project(name)
    if project_id == None:
        print "[+] Error: Could not find project with name '%s'." % name
        sys.exit(2)
    
    return project_id


def find_subdomains(domain):
    print "[+] Running sublist3r to find subdomains of %s..." % domain
    return sublist3r.main(domain, 40, '', ports= None, silent=True, verbose=True, enable_bruteforce=True, engines=None)


def is_in_scope(ip, scope):
    for network in scope:
        netw = int(network.network_address)
        mask = int(network.netmask)
        a = int(ipaddress.ip_address(ip.decode()))
        if (a & mask) == netw:
            return True
    
    return False

def locate_node(pd, project_id, ip):
    return pd.find_node(project_id, "plugin.output/" + ip)


def update_hostnames(pd, project_id, node_id, hostnames):
    nmap_host_note_id = pd.find_note(project_id, node_id, ["Hostnames"])[0][1]
    nmap_host_note = pd.get_note(project_id, node_id, nmap_host_note_id)
    ip = nmap_host_note["fields"]["IP"]
    text = nmap_host_note["text"]
    category_id = nmap_host_note["category_id"]
    
    hostnames_index = text.find("#[Hostnames]#")
    hostnames_end_index = text.find("#[OS]#")
    hostnames_field = text[hostnames_index:hostnames_end_index].strip()
    hostnames_field += "\r\n"

    updated = False
    for hostname in hostnames:
        if hostname not in hostnames_field:
            print "[+] Adding %s to %s" % (hostname, ip)
            hostnames_field += hostname + "\r\n"
            updated = True
        else:
            print "[+] Hostname %s already exists for %s" % (hostname, ip)

    hostnames_field += "\r\n"
    
    updated_text = text[:hostnames_index] + hostnames_field + text[hostnames_end_index:]
    if updated:
        print "[+] Updating hostnames for %s" % ip
        pd.update_note(project_id, node_id, nmap_host_note_id, updated_text, category=category_id)


if __name__ == "__main__":
    domains, scope, project_name = parse_cli_options(sys.argv)
    if len(scope) == 0:
        print "[+] No scope defined. Assuming all IP addresses are in-scope."
        scope.append(ipaddress.ip_network("0.0.0.0/0".decode()))
    
    pd = init_dradis()
    project_id = find_project_id(pd, project_name)

    Resolver = dns.resolver.Resolver()
    Resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    results = {}
    for domain in domains:
        results[domain] = find_subdomains(domain)
        print "[+] Found %d in-scope subdomains for %s" % (len(results[domain]), domain)
    
    print "[+] Resolving subdomains in DNS..."
    nodes = {}
    for domain, subdomains in results.iteritems():
        for subdomain in subdomains:
            try:
                ip = Resolver.query(subdomain, 'A')[0].to_text()
            except:
                continue
            if ip:
                if is_in_scope(ip, scope):
                    try:
                        print "[+] %s resolves to %s" % (subdomain, ip)
                        nodes[ip].append(subdomain)
                    except KeyError:
                        nodes[ip] = [subdomain]
    
    for node in nodes.keys():
        node_id = locate_node(pd, project_id, node)
        if not node_id:
            print "[-] %s is in-scope but there was no node found in Dradis. Double-check your Nmap scan." % node
            continue
        update_hostnames(pd, project_id, node_id, nodes[node])
