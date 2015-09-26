#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import subprocess
import argparse
import time
import sys
import os
import re

from . import color
from .logger import Logger
logger = Logger.logger

# Logger.add_file_handler('./iker.log')
# Logger.remove_console_handler()
# logger.debug("debug level enabled")
# Logger.set_verbose('debug')

__version__ = "2.1"

IKESCAN_PATH = None
search_paths = ["/usr/bin/ike-scan", "/sbin/ike-scan", "/bin/ike-scan"]

for exe in search_paths:
    if os.path.exists(os.path.realpath(exe)):
        IKESCAN_PATH = (os.path.realpath(exe))
if IKESCAN_PATH is None:
    raise Exception("Cannot locate ike-scan in {0}".format(search_paths))

VERBOSE = False

# Encryption algorithms: DES, Triple-DES, AES/128, AES/192 and AES/256
ENCLIST = []
HASHLIST = []   # Hash algorithms: MD5 and SHA1
# Authentication methods: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH
AUTHLIST = []
GROUPLIST = []  # Diffie-Hellman groups: 1, 2 and 5

# Full algorithms lists
FULLENCLIST = ['1', '2', '3', '4', '5', '6', '7/128', '7/192', '7/256', '8']
FULLHASHLIST = ['1', '2', '3', '4', '5', '6']
FULLAUTHLIST = [
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '64221',
    '64222',
    '64223',
    '64224',
    '65001',
    '65002',
    '65003',
    '65004',
    '65005',
    '65006',
    '65007',
    '65008',
    '65009',
    '65010']
FULLGROUPLIST = [
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    '10',
    '11',
    '12',
    '13',
    '14',
    '15',
    '16',
    '17',
    '18']
XMLOUTPUT = "output.xml"
CLIENTIDS = ""
DELAY = 0

# Issues
FLAWVPNDISCOVERABLEC = "\033[93m[+]\033[0m The IKE service could be discovered (Risk: LOW)"
FLAWIKEV2SUPPORTEDC = "\033[93m[+]\033[0m IKE v2 is supported (Risk: Informational)"
FLAWVPNFINGVIDC = "\033[93m[+]\033[0m The IKE service could be fingerprinted by analysing the vendor ID (VID) returned (Risk: LOW)"
FLAWVPNFINGBACKOFFC = "\033[93m[+]\033[0m The IKE service could be fingerprinted by analysing the responses received (Risk: LOW)"
FLAWWEAKENCALGC = "\033[93m[+]\033[0m The following weak encryption algorithm was supported: DES (Risk: MEDIUM)"
FLAWWEAKHASHALGC = "\033[93m[+]\033[0m The following weak hash algorithm was supported: MD5 (Risk: MEDIUM)"
FLAWWEAKDHGALGC = "\033[93m[+]\033[0m The following weak Diffie-Hellman group was supported: MODP-768 (Risk: MEDIUM)"
FLAWWEAKDH2GALGC = "\033[93m[+]\033[0m The following weak Diffie-Hellman group was supported: DH Group 2 (Risk: MEDIUM)"
FLAWAGGRESSIVEC = "\033[93m[+]\033[0m Aggressive Mode was accepted by the IKE service (Risk: MEDIUM)"
FLAWAGGRGROUPNOENCC = "\033[93m[+]\033[0m Aggressive Mode transmits group name without encryption (Risk: LOW)"
FLAWCIDENUMERATIONC = "\033[93m[+]\033[0m Client IDs could be enumerated (Risk: MEDIUM)"

FLAWVPNDISCOVERABLE = "The IKE service could be discovered (Risk: LOW)"
FLAWIKEV2SUPPORTED = "IKE v2 is supported (Risk: Informational)"
FLAWVPNFINGVID = "The IKE service could be fingerprinted by analysing the vendor ID (VID) returned (Risk: LOW)"
FLAWVPNFINGBACKOFF = "The IKE service could be fingerprinted by analysing the responses received (Risk: LOW)"
FLAWWEAKENCALG = "The following weak encryption algorithm was supported: DES (Risk: MEDIUM)"
FLAWWEAKHASHALG = "The following weak hash algorithm was supported: MD5 (Risk: MEDIUM)"
FLAWWEAKDHGALG = "The following weak Diffie-Hellman group was supported: MODP-768 (Risk: MEDIUM)"
FLAWWEAKDH2GALG = "The following weak Diffie-Hellman group was supported: DH Group 2 (Risk: MEDIUM)"
FLAWAGGRESSIVE = "Aggressive Mode was accepted by the IKE service (Risk: MEDIUM)"
FLAWAGGRGROUPNOENC = "Aggressive Mode transmits group name without encryption (Risk: LOW)"
FLAWCIDENUMERATION = "Client IDs could be enumerated (Risk: MEDIUM)"


def banner():
    """
    Prints a banner message.
    """
    print("ike-scan wrapper for testing IPsec-based VPNs.")


def check_privileges():
    """
    This method checks if the script was launched with root privileges.
        @returns True if it was launched with root privs and False in other case.
    """
    return os.geteuid() == 0


def get_arguments():
    """
    Parses command line options
        @returns the arguments received and a list of targets.
    """
    global IKESCAN_PATH
    global ENCLIST
    global HASHLIST
    global AUTHLIST
    global GROUPLIST
    global XMLOUTPUT
    global CLIENTIDS
    global DELAY

    targets = []

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "target",
        type=str,
        nargs='?',
        help="The IP address or the network (CIDR notation) to scan.")

    parser.add_argument(
        "-l",
        "--loglevel",
        action="store",
        type=str,
        default='info',
        help="logging verbose level")
    parser.add_argument(
        "-d",
        "--delay",
        type=int,
        help="Delay between requests (in milliseconds). Default: 0 (No delay).")
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        help="An input file with an IP address/network per line.")
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="An output file to store the results.")
    parser.add_argument(
        "-x",
        "--xml",
        type=str,
        help="An output file to store the results in XML format. Default: output.xml")
    parser.add_argument(
        "--encalgs",
        type=str,
        default="1 5 7/128 7/192 7/256",
        help="The encryption algorithms to check. Default: DES, 3DES, AES/128, AES/192 and AES/256. "
        "Example: --encalgs=\"1 5 7/128 7/192 7/256\"")
    parser.add_argument(
        "--hashalgs",
        type=str,
        default="1 2",
        help="The hash algorithms to check. Default: MD5 and SHA1. Example: --hashalgs=\"1 2\"")
    parser.add_argument(
        "--authmethods",
        type=str,
        default="1 3 64221 65001",
        help="The authorization methods to check. Default: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH. "
        "Example: --authmethods=\"1 3 64221 65001\"")
    parser.add_argument(
        "--dhgroups",
        type=str,
        default="1 2 5",
        help="The Diffie-Hellman groups to check. Default: MODP 768, MODP 1024 and MODP 1536. "
        "Example: --dhgroups=\"1 2 5\"")
    parser.add_argument(
        "--fullalgs",
        action="store_true",
        help="Equivalent to: "
        "--encalgs=\"1 2 3 4 5 6 7/128 7/192 7/256 8\" "
        "--hashalgs=\"1 2 3 4 5 6\" "
        "--authmethods=\"1 2 3 4 5 6 7 8 64221 64222 64223 64224 65001 65002 65003 65004 65005 65006 65007 65008 65009 65010\" "
        "--dhgroups=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18\"")
    parser.add_argument(
        "--ikepath",
        type=str,
        help="The FULL ike-scan path if it is not in the PATH variable and/or the name changed.")
    parser.add_argument(
        "-c",
        "--clientids",
        type=str,
        help="A file (dictionary) with a client ID per line to enumerate valid client IDs in Aggressive Mode. "
        "This test is not launched by default.")

    args = parser.parse_args()
    Logger.set_verbose(args.loglevel)

    if args.target:
        targets.append(args.target)

    if args.input:
        try:
            f = open(args.input, "r")
            targets.extend(f.readlines())
            f.close()
        except:
            logger.error(
                "The input file specified ('%s') could not be opened." %
                args.input)

    if args.output:
        try:
            f = open(args.output, "w")
            f.close()
        except:
            logger.error(
                "The output file specified ('%s') could not be opened/created." %
                args.output)

    if not targets:
        logger.error("You need to specify a target or an input file (-i)")
        parser.parse_args(["-h"])
        sys.exit(1)

    if args.ikepath:
        IKESCAN_PATH = args.ikepath

    if args.encalgs:
        ENCLIST = args.encalgs.split()
        for alg in ENCLIST:
            parts = alg.split('/')
            for p in parts:
                if not p.isdigit():
                    logger.fatal(
                        "Wrong syntax for the encalgs parameter. Check syntax.")
                    parser.parse_args(["-h"])
                    sys.exit(1)

    if args.hashalgs:
        HASHLIST = args.hashalgs.split()
        for alg in HASHLIST:
            if not alg.isdigit():
                logger.fatal(
                    "Wrong syntax for the hashalgs parameter. Check syntax.")
                parser.parse_args(["-h"])
                sys.exit(1)

    if args.authmethods:
        AUTHLIST = args.authmethods.split()
        for alg in AUTHLIST:
            if not alg.isdigit():
                logger.fatal(
                    "Wrong syntax for the authmethods parameter. Check syntax.")
                parser.parse_args(["-h"])
                sys.exit(1)

    if args.dhgroups:
        GROUPLIST = args.dhgroups.split()
        for alg in GROUPLIST:
            if not alg.isdigit():
                logger.fatal(
                    "Wrong syntax for the dhgroups parameter. Check syntax.")
                parser.parse_args(["-h"])
                sys.exit(1)

    if args.xml:
        XMLOUTPUT = args.xml
    try:
        f = open(XMLOUTPUT, "w")
        f.close()
    except:
        logger.error("The XML output file could not be opened/created.")

    if args.clientids:
        try:
            f = open(args.clientids, "r")
            f.close()
            CLIENTIDS = args.clientids
        except:
            logger.error(
                "\033[91m[*]\033[0m The client ID dictionary could not be read. This test won't be launched.")

    if args.delay:
        DELAY = args.delay

    if args.fullalgs:
        ENCLIST = FULLENCLIST
        HASHLIST = FULLHASHLIST
        AUTHLIST = FULLAUTHLIST
        GROUPLIST = FULLGROUPLIST

    return args, targets


def launch_proccess(command):
    """
    Launches a command in a different process and return the process.
    """
    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    error = process.stderr.readlines()
    if len(error) > 0 and "ERROR" in error[0] and "port 500" in error[0]:
        logger.fatal(
            "\033[91m[*]\033[0m Port already binded. Is another instance of ike-scan running?.")
        sys.exit(1)
    else:
        return process


def usleep(secs):
    """
    Sleeps secs/1000
    @param secs Sleep time
    """
    time.sleep(secs / 1000.0)


def wait_for_exit(args, vpns, ip, key, value):
    """
    This method shows a progressbar during the discovery of transforms.
        @param top The total number of transforms combinations
        @param current The iteration within the bucle (which transform is checking).
        @param transform The string which represent the transform.
    """
    try:
        logger.alert(
            "Ctrl+C pressed. Do it again to sys.exit or wait to continue but skipping this step")
        vpns[ip][key] = value
        sleep(2)
        if key not in vpns[ip].keys() or not vpns[ip][key]:
            logger.info("Skipping current test")
    except KeyboardInterrupt:
        parse_results(args, vpns)
        logger.info(
            "Finished at %s" %
            time.strftime(
                "%a, %d %b %Y %H:%M:%S",
                time.localtime()))
        sys.exit(0)


def update_progress_bar(top, current, transform):
    """
    Updates the progressbar during the discovery of transforms.
        @param top The total number of transforms combinations
        @param current The iteration within the bucle (which transform is checking).
        @param transform The string which represent the transform.
    """

    progressbar = "[....................] %d%% - Current transform: %s\r"
    tt = 20
    step = top / tt
    cc = current / step
    progressbar = progressbar.replace(".", "=", cc)
    perctg = current * 100 / top
    sys.stdout.write(progressbar % (perctg, transform))
    sys.stdout.flush()


def check_ike_scan():
    """
    Checks for the ike-scan location.
        @return True if ike-scan was found and False in other case.
    """
    proccess = subprocess.Popen(
        "%s --version" %
        IKESCAN_PATH,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    proccess.wait()
    output = proccess.stderr.read()

    if "ike-scan" in output.lower():
        return True
    else:
        return False


def discovery(args, targets, vpns):
    """
    Run ike-scan to discover IKE services and update the vpns variable with the information found.
        @param args The command line parameters
        @param targets The targets specified (IPs and/or networks)
        @param vpns A dictionary to store all the information
    """
    logger.info("Discovering IKE services, please wait")

    for target in targets:
        process = launch_proccess("%s -M %s" % (IKESCAN_PATH, target))
        process.wait()
        ip = None
        info = ""
        for line in process.stdout.readlines():
            if not line.split(
            ) or "Starting ike-scan" in line or "Ending ike-scan" in line:
                continue
            if line[0].isdigit():
                if info:
                    vpns[ip] = {}
                    vpns[ip]["handshake"] = info.strip()
                    if VERBOSE:
                        logger.info(info)
                    else:
                        logger.info(
                            "IKE service identified at: {0}".format(ip))

                ip = line.split()[0]
                info = line
            else:
                info = info + line
        if info and ip not in vpns.keys():
            vpns[ip] = {}
            vpns[ip]["handshake"] = info.strip()
            logger.debug(info)
            logger.info("IKE service identified at: %s" % ip)


def check_ike_v2(args, targets, vpns):
    """This method checks if IKE version 2 is supported.
    @param args The command line parameters
    @param vpns A dictionary to store all the information"""

    logger.info("Checking for IKE version 2 support")
    ips = []

    try:
        # Check the IKE v2 support
        for target in targets:

            process = launch_proccess("%s -2 -M %s" % (IKESCAN_PATH, target))
            process.wait()

            ip = None
            info = ""

            for line in process.stdout.readlines():

                if not line.split(
                ) or "Starting ike-scan" in line or "Ending ike-scan" in line:
                    continue

                if line[0].isdigit():

                    if info:
                        logger.info(
                            "\033[92m[*]\033[0m IKE version 2 is supported by %s" %
                            ip)
                        ips.append(ip)
                        if ip in vpns.keys():
                            vpns[ip]["v2"] = True
                        else:
                            logger.info(
                                "IKE version 1 support was not identified in this host (%s). iker will not perform more tests against this host." %
                                ip)
                    ip = line.split()[0]
                    info = line

            if info and ip not in ips:
                logger.info(
                    "\033[92m[*]\033[0m IKE version 2 is supported by %s" %
                    ip)
                if ip in vpns.keys():
                    vpns[ip]["v2"] = True
                else:
                    logger.info(
                        "IKE version 1 support was not identified in this host (%s). iker will not perform more tests against this host." %
                        ip)

        # Complete those which don't support it
        for ip in vpns.keys():

            if "v2" not in vpns[ip].keys():
                vpns[ip]["v2"] = False
    except KeyboardInterrupt:
        wait_for_exit(args, vpns, ip, "v2", False)


def fingerprint_VID(args, vpns, handshake=None):
    """
    Discovers the vendor of the devices by checking the VID.
    Results are written in the vpns variable.
        @param args The command line parameters
        @param vpns A dictionary to store all the information
        @param handshake The handshake where look for a VID
    """
    for ip in vpns.keys():
        if "vid" not in vpns[ip].keys():
            vpns[ip]["vid"] = []

        # Fingerprint based on VIDs
        hshk = vpns[ip]["handshake"]
        if handshake:
            if ip in handshake:
                hshk = handshake
            else:
                continue
        transform = ""
        vid = ""
        for line in hshk.splitlines():

            if "SA=" in line:
                transform = line.strip()[4:-1]

            if "VID=" in line \
                    and "(" in line and ")" in line \
                    and "draft-ietf" not in line \
                    and "IKE Fragmentation" not in line \
                    and "Dead Peer Detection" not in line \
                    and "XAUTH" not in line \
                    and "RFC 3947" not in line \
                    and "Heartbeat Notify" not in line:
                vid = line[line.index('(') + 1:line.index(')')]

        enc = False
        for pair in vpns[ip]["vid"]:
            if pair[0] == vid:
                enc = True

        if vid and not enc:
            vpns[ip]["vid"].append((vid, hshk))
            logger.info(
                "\033[92m[*]\033[0m Vendor ID identified for IP %s with transform %s: %s" %
                (ip, transform, vid))


def fingerprint_show_backoff(args, vpns, transform="", vpnip=""):
    """
    Discover the vendor of the devices and the results are written in the vpns variable.
        @param args The command line parameters
        @param vpns A dictionary to store all the information
    """
    logger.info(
        "Trying to fingerprint the device %s (1-5 minutes per IP)" %
        (transform and " (again)" or transform))

    try:
        for ip in vpns.keys():

            if vpnip and vpnip != ip:
                continue

            process = launch_proccess(
                "%s --showbackoff %s %s" %
                (IKESCAN_PATH,
                 ((transform and (
                     "--trans=" +
                     transform) or transform)),
                    ip))
            vpns[ip]["showbackoff"] = ""
            process.wait()

            # Fingerprint based on the VPN service behaviour
            for line in process.stdout.readlines():

                if "Implementation guess:" in line:

                    vendor = line[
                        line.index('Implementation guess:') +
                        22:].strip()

                    if vendor.lower() != "unknown":

                        vpns[ip]["showbackoff"] = vendor

                        logger.info(
                            "\033[92m[*]\033[0m Implementation guessed for IP %s: %s" %
                            (ip, vendor))

            if not vpns[ip]["showbackoff"]:
                if transform:
                    logger.info(
                        "\033[91m[*]\033[0m The device %s could not been fingerprinted. It won't be retry again." %
                        ip)
                    vpns[ip]["showbackoff"] = " "
                else:
                    logger.info(
                        "\033[91m[*]\033[0m The device %s could not been fingerprinted because no transform is known." %
                        ip)
    except KeyboardInterrupt:
        wait_for_exit(args, vpns, ip, "showbackoff", " ")


def check_encription_algorithms(args, vpns):
    """
    Discovers accepted transforms. The results     are written in the vpns variable.
        @param args The command line parameters
        @param vpns A dictionary to store all the information
    """
    try:
        top = len(ENCLIST) * len(HASHLIST) * len(AUTHLIST) * len(GROUPLIST)
        current = 0
        for ip in vpns.keys():

            logger.info("Looking for accepted transforms at %s" % ip)
            vpns[ip]["transforms"] = []

            for enc in ENCLIST:
                for hsh in HASHLIST:
                    for auth in AUTHLIST:
                        for group in GROUPLIST:

                            process = launch_proccess(
                                "%s -M --trans=%s,%s,%s,%s %s" %
                                (IKESCAN_PATH, enc, hsh, auth, group, ip))
                            process.wait()

                            output = process.stdout.read()
                            info = ""
                            new = False
                            for line in output.splitlines():

                                if "Starting ike-scan" in line or "Ending ike-scan" in line or line.strip() == "":
                                    continue

                                info += line + "\n"

                                if "SA=" in line:
                                    new = True
                                    transform = line.strip()[4:-1]
                                    logger.info(
                                        "\033[92m[*]\033[0m Transform found: %s" %
                                        transform)

                            if new:
                                vpns[ip]["transforms"].append(
                                    ("%s,%s,%s,%s" %
                                     (enc, hsh, auth, group), transform, info))
                                fingerprint_VID(args, vpns, info)
                                # If the backoff could not been fingerprinted
                                # before...
                                if not vpns[ip]["showbackoff"]:
                                    fingerprint_show_backoff(
                                        args,
                                        vpns,
                                        vpns[ip]["transforms"][0][0],
                                        ip)

                            current += 1
                            update_progress_bar(
                                top,
                                current,
                                str(enc) +
                                "," +
                                str(hsh) +
                                "," +
                                str(auth) +
                                "," +
                                str(group))
                            usleep(DELAY)
    except KeyboardInterrupt:
        if "transforms" not in vpns[ip].keys() or not vpns[ip]["transforms"]:
            wait_for_exit(args, vpns, ip, "transforms", [])
        else:
            wait_for_exit(args, vpns, ip, "transforms", vpns[ip]["transforms"])


def check_aggressives(args, vpns):
    """
    Checks if aggressive mode is available. If so, it also store the returned handshake to a text file.
        @param args The command line parameters
        @param vpns A dictionary to store all the information
    """
    try:
        top = len(ENCLIST) * len(HASHLIST) * len(AUTHLIST) * len(GROUPLIST)
        current = 0
        for ip in vpns.keys():

            logger.info(
                "Looking for accepted transforms in aggressive mode at %s" %
                ip)
            vpns[ip]["aggressive"] = []

            for enc in ENCLIST:
                for hsh in HASHLIST:
                    for auth in AUTHLIST:
                        for group in GROUPLIST:
                            process = launch_proccess(
                                "%s -M --aggressive -P%s_handshake.txt --trans=%s,%s,%s,%s %s" %
                                (IKESCAN_PATH, ip, enc, hsh, auth, group, ip))
                            process.wait()
                            output = process.stdout.read()
                            info = ""
                            new = False
                            for line in output.splitlines():
                                if "Starting ike-scan" in line or "Ending ike-scan" in line or line.strip() == "":
                                    continue
                                info += line + "\n"
                                if "SA=" in line:
                                    new = True
                                    transform = line.strip()[4:-1]
                                    logger.info(
                                        "\033[92m[*]\033[0m Aggressive mode supported with transform: %s" %
                                        transform)

                            if new:
                                vpns[ip]["aggressive"].append(
                                    ("%s,%s,%s,%s" %
                                     (enc, hsh, auth, group), transform, info))
                                fingerprint_VID(args, vpns, info)
                                # If the backoff could not been fingerprinted
                                # before...
                                if not vpns[ip]["showbackoff"]:
                                    fingerprint_show_backoff(
                                        args,
                                        vpns,
                                        vpns[ip]["aggressive"][0][0],
                                        ip)

                            current += 1
                            update_progress_bar(
                                top,
                                current,
                                str(enc) +
                                "," +
                                str(hsh) +
                                "," +
                                str(auth) +
                                "," +
                                str(group))
                            usleep(DELAY)
    except KeyboardInterrupt:
        if "aggressive" not in vpns[ip].keys() or not vpns[ip]["aggressive"]:
            wait_for_exit(args, vpns, ip, "aggressive", [])
        else:
            wait_for_exit(args, vpns, ip, "aggressive", vpns[ip]["aggressive"])


def enumerate_groupID_ciscoDPD(args, vpns, ip):
    """
    Enumerates valid client IDs from a dictionary.
        @param args The command line parameters
        @param vpns A dictionary to store all the information
        @param ip The ip where perform the enumeration
    """
    process = launch_proccess(
        "%s --aggressive --trans=%s --id=badgroupiker573629 %s" %
        (IKESCAN_PATH, vpns[ip]["aggressive"][0][0], ip))
    process.wait()
    possible = True
    for line in process.stdout.readlines():
        if "dead peer" in line.lower():
            possible = False
            break
    if possible:
        usleep(DELAY)
        try:
            fdict = open(args.clientids, "r")
            cnt = 0

            for cid in fdict:
                cid = cid.strip()

                process = launch_proccess(
                    "%s --aggressive --trans=%s --id=%s %s" %
                    (IKESCAN_PATH, vpns[ip]["aggressive"][0][0], cid, ip))
                process.wait()

                output = process.stdout.readlines()[1].strip()

                # Check if the service is still responding
                msg = re.sub(r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', output)
                if not msg:
                    cnt += 1
                    if cnt > 3:
                        logger.error(
                            "\033[91m[*]\033[0m The IKE service cannot be reached; a firewall might filter your IP address.")
                        logger.error(
                            "DPD Group ID enumeration could not be performed.")
                        return False

                enc = False
                for line in output:
                    if "dead peer" in line.lower():
                        enc = True
                        break
                usleep(DELAY)
                # Re-check the same CID if it looked valid
                if enc:
                    process = launch_proccess(
                        "%s --aggressive --trans=%s --id=%s %s" %
                        (IKESCAN_PATH, vpns[ip]["aggressive"][0][0], cid, ip))
                    process.wait()

                    enc = False
                    for line in process.stdout.readlines():
                        if "dead peer" in line.lower():
                            vpns[ip]["clientids"].append(cid)
                            logger.info(
                                "\033[92m[*]\033[0m A potential valid client ID was found: %s" %
                                cid)
                            break
                    usleep(DELAY)
            fdict.close()
        except:
            possible = False
    return possible


def enumerate_group_id(args, vpns):
    """
    Enumerates valid client IDs from a dictionary.
        @param args The command line parameters
        @param vpns A dictionary to store all the information
    """
    if not args.clientids:
        return
    for ip in vpns.keys():
        vpns[ip]["clientids"] = []
        if not len(vpns[ip]["aggressive"]):
            continue
        logger.info("Trying to enumerate valid client IDs for IP %s" % ip)

        # Check if the device is vulnerable to Cisco DPD group ID enumeration
        # and exploit it
        done = False
        if "showbackoff" in vpns[
                ip].keys() and "cisco" in vpns[ip]["showbackoff"].lower():
            done = enumerate_groupID_ciscoDPD(args, vpns, ip)

        if "vid" in vpns[ip].keys() and len(vpns[ip]["vid"]) > 0:
            for vid in vpns[ip]["vid"]:
                if "cisco" in vid[0].lower():
                    done = enumerate_groupID_ciscoDPD(args, vpns, ip)
                    break
        if done:
            # if not len (vpns[ip]["clientids"]):
            continue  # If Cisco DPD enumeration, continue

        # Try to guess the "unvalid client ID" message
        process = launch_proccess(
            "%s --aggressive --trans=%s --id=badgroupiker123456 %s" %
            (IKESCAN_PATH, vpns[ip]["aggressive"][0][0], ip))
        process.wait()
        message1 = re.sub(
            r'(HDR=\()[^\)]*(\))',
            r'\1xxxxxxxxxxx\2',
            process.stdout.readlines()[1].strip())
        usleep(DELAY)

        process = launch_proccess(
            "%s --aggressive --trans=%s --id=badgroupiker654321 %s" %
            (IKESCAN_PATH, vpns[ip]["aggressive"][0][0], ip))
        process.wait()
        message2 = re.sub(
            r'(HDR=\()[^\)]*(\))',
            r'\1xxxxxxxxxxx\2',
            process.stdout.readlines()[1].strip())
        usleep(DELAY)

        process = launch_proccess(
            "%s --aggressive --trans=%s --id=badgroupiker935831 %s" %
            (IKESCAN_PATH, vpns[ip]["aggressive"][0][0], ip))
        process.wait()
        message3 = re.sub(
            r'(HDR=\()[^\)]*(\))',
            r'\1xxxxxxxxxxx\2',
            process.stdout.readlines()[1].strip())
        usleep(DELAY)

        invalidmsg = ""
        if message1 == message2:
            invalidmsg = message1
            if message1 != message3:
                vpns[ip]["clientids"].append("badgroupiker935831")
        elif message1 == message3:
            invalidmsg = message1
            vpns[ip]["clientids"].append("badgroupiker654321")
        elif message2 == message3:
            invalidmsg = message2
            vpns[ip]["clientids"].append("badgroupiker123456")
        else:
            logger.error(
                "\033[91m[*]\033[0m It was not possible to get a common response to invalid client IDs. This test will be skipped.")
            return

        # Enumerate users
        try:
            fdict = open(args.clientids, "r")
            cnt = 0
            for cid in fdict:
                cid = cid.strip()
                process = launch_proccess(
                    "%s --aggressive --trans=%s --id=%s %s" %
                    (IKESCAN_PATH, vpns[ip]["aggressive"][0][0], cid, ip))
                process.wait()
                msg = re.sub(
                    r'(HDR=\()[^\)]*(\))',
                    r'\1xxxxxxxxxxx\2',
                    process.stdout.readlines()[1].strip())

                if not msg:
                    cnt += 1
                    if cnt > 3:
                        logger.error(
                            "\033[91m[*]\033[0m The IKE service cannot be reached")
                        logger.error("Skippig to the following service")
                        break
                elif msg != invalidmsg:
                    vpns[ip]["clientids"].append(cid)
                    logger.info(
                        "\033[92m[*]\033[0m A potential valid client ID was found: %s" %
                        cid)
                usleep(DELAY)
            fdict.close()
        except:
            pass


def parse_results(args, vpns):
    """
    Analyses the results and prints them where correspond.
        @param args The command line parameters
        @param vpns A dictionary to store all the information
    """
    logger.info("Results:")
    pathxml = XMLOUTPUT
    try:
        fxml = open(pathxml, "a")
        fxml.write("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<services>\n")
    except:
        pass

    for ip in vpns.keys():
        try:
            fxml.write("\t<service ip=\"%s\">\n\t\t<flaws>\n" % ip)
        except:
            pass

        # Discoverable
        logger.info("Resuls for IP %s:" % ip)
        logger.info("%s" % FLAWVPNDISCOVERABLEC)

        try:
            fxml.write(
                "\t\t\t<flaw flawid=\"1\" description=\"%s\"><![CDATA[%s]]></flaw>\n" %
                (FLAWVPNDISCOVERABLE, vpns[ip]["handshake"]))
        except:
            pass

        # IKE v2
        if "v2" in vpns[ip].keys() and vpns[ip]["v2"]:
            logger.info("%s" % FLAWIKEV2SUPPORTEDC)
            try:
                fxml.write(
                    "\t\t\t<flaw flawid=\"10\" description=\"%s\"></flaw>\n" %
                    FLAWIKEV2SUPPORTED)
            except:
                pass

        # Fingerprinted by VID
        if "vid" in vpns[ip].keys() and len(vpns[ip]["vid"]) > 0:
            logger.info("%s" % FLAWVPNFINGVIDC)
            for pair in vpns[ip]["vid"]:
                logger.info("%s" % pair[0])
                logger.debug("%s" % pair[1])
                try:
                    fxml.write(
                        "\t\t\t<flaw flawid=\"2\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" %
                        (FLAWVPNFINGVID, pair[0], pair[1]))
                except:
                    pass

        # Fingerprinted by back-off
        if "showbackoff" in vpns[
                ip].keys() and vpns[ip]["showbackoff"].strip():
            logger.info(
                "%s: %s" %
                (FLAWVPNFINGBACKOFFC, vpns[ip]["showbackoff"]))
            try:
                fxml.write(
                    "\t\t\t<flaw flawid=\"3\" description=\"%s\" value=\"%s\"></flaw>\n" %
                    (FLAWVPNFINGBACKOFF, vpns[ip]["showbackoff"]))
            except:
                pass

        # Weak encryption/hash/DH group algorithm
        first = True
        if "transforms" in vpns[ip].keys():
            for trio in vpns[ip]["transforms"]:
                if "Enc=DES" in trio[1]:
                    if first:
                        first = False
                        logger.info("%s" % FLAWWEAKENCALGC)
                    logger.debug("%s" % trio[2])
                    try:
                        fxml.write(
                            "\t\t\t<flaw flawid=\"4\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" %
                            (FLAWWEAKENCALG, trio[1], trio[2]))
                    except:
                        pass
            first = True
            for trio in vpns[ip]["transforms"]:
                if "Hash=MD5" in trio[1]:
                    if first:
                        first = False
                        logger.info("%s" % FLAWWEAKHASHALGC)
                    logger.debug("%s" % trio[2])
                    try:
                        fxml.write(
                            "\t\t\t<flaw flawid=\"5\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" %
                            (FLAWWEAKHASHALG, trio[1], trio[2]))
                    except:
                        pass

            first = True
            for trio in vpns[ip]["transforms"]:
                if "Group=1:modp768" in trio[1]:
                    if first:
                        first = False
                        logger.info("%s" % FLAWWEAKDHGALGC)
                    logger.debug("%s" % trio[2])
                    try:
                        fxml.write(
                            "\t\t\t<flaw flawid=\"6\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" %
                            (FLAWWEAKDHGALG, trio[1], trio[2]))
                    except:
                        pass
            first = True
            for trio in vpns[ip]["transforms"]:
                if "Group=2" in trio[1]:
                    if first:
                        first = False
                        logger.info("%s" % FLAWWEAKDH2GALGC)
                    logger.debug("%s" % trio[2])
                    try:
                        fxml.write(
                            "\t\t\t<flaw flawid=\"6\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" %
                            (FLAWWEAKDH2GALG, trio[1], trio[2]))
                    except:
                        pass

        # Aggressive Mode ?
        if "aggressive" in vpns[ip].keys() and len(vpns[ip]["aggressive"]) > 0:
            logger.info("%s" % FLAWAGGRESSIVEC)
            for trio in vpns[ip]["aggressive"]:
                logger.info("\t%s" % (trio[1]))
                logger.debug("%s" % (trio[2]))
                try:
                    fxml.write(
                        "\t\t\t<flaw flawid=\"7\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" %
                        (FLAWAGGRESSIVE, trio[1], trio[2]))
                except:
                    pass
            logger.info("%s" % FLAWAGGRGROUPNOENCC)
            try:
                fxml.write(
                    "\t\t\t<flaw flawid=\"8\" description=\"%s\"></flaw>\n" %
                    (FLAWAGGRGROUPNOENC))
            except:
                pass

        # Client IDs ?
        if "clientids" in vpns[ip].keys() and len(vpns[ip]["clientids"]) > 0:
            logger.info(
                "%s: %s" %
                (FLAWCIDENUMERATIONC,
                 ", ".join(
                     vpns[ip]["clientids"])))
            try:
                fxml.write(
                    "\t\t\t<flaw flawid=\"9\" description=\"%s\" value=\"%s\"></flaw>\n" %
                    (FLAWCIDENUMERATION,
                     ", ".join(
                         vpns[ip]["clientids"])))
            except:
                pass
        try:
            fxml.write("\t\t</flaws>\n\t</service>\n")
        except:
            pass
    try:
        fxml.write("</services>\n")
        fxml.close()
    except:
        pass


def main():

    if not check_privileges():
        logger.fatal("\033[91m[*]\033[0m got r00t?")
        sys.exit(1)

    banner()
    vpns = {}
    args, targets = get_arguments()

    if not check_ike_scan():
        logger.fatal(
            "\033[91m[*]\033[0m ike-scan could not be found. Please specified the full path with the --ikepath option.")
        sys.exit(2)

    logger.info(
        "Starting at %s" %
        time.strftime(
            "%a, %d %b %Y %H:%M:%S",
            time.localtime()))

    # 1. Discovery
    discovery(args, targets, vpns)
    check_ike_v2(args, targets, vpns)

    if not len(vpns.keys()):
        logger.critical("No IKE service was found")
        sys.exit(0)

    # 2. Fingerprint by checking VIDs and by analysing the service responses
    fingerprint_VID(args, vpns)
    fingerprint_show_backoff(args, vpns)
    # 3. Ciphers
    check_encription_algorithms(args, vpns)
    # 4. Aggressive Mode
    check_aggressives(args, vpns)
    # 5. Enumerate client IDs
    enumerate_group_id(args, vpns)
    # . Parse the results
    parse_results(args, vpns)

    logger.info(
        "Finished at %s" %
        time.strftime(
            "%a, %d %b %Y %H:%M:%S",
            time.localtime()))
