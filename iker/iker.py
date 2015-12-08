#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import argparse
import time
import sys
import os
import re

from . import color
from . import ike_scan_wrapper
from .logger import Logger

logger = Logger.logger


def banner():
    """
    Prints a banner message.
    """
    print("ike-scan wrapper for testing IPsec-based VPNs.")


def get_arguments():
    """
    Parses command line options
        @returns the arguments received and a list of targets.
    """
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
        default=None,
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
        self.ikescan_path = args.ikepath

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


def main(argv=sys.argv[1:]):

    if os.geteuid():
        logger.fatal("got r00t?")
        return 10

    banner()
    vpns = {}
    args, targets = get_arguments()

    wrapper = ike_scan_wrapper.IkeScanWrapper(output=args.output)

    logger.info("Starting at %s" % time.strftime(
            "%a, %d %b %Y %H:%M:%S",time.localtime()))

    # 1. Discovery
    wrapper.discovery(args, targets, vpns)
    wrapper.check_ike_v2(args, targets, vpns)

    if not len(vpns.keys()):
        logger.critical("No IKE service was found")
        sys.exit(0)

    # 2. Fingerprint by checking VIDs and by analysing the service responses
    wrapper.fingerprint_VID(args, vpns)
    wrapper.fingerprint_show_backoff(args, vpns)
    # 3. Ciphers
    wrapper.check_encription_algorithms(args, vpns)
    # 4. Aggressive Mode
    wrapper.check_aggressives(args, vpns)
    # 5. Enumerate client IDs
    wrapper.enumerate_group_id(args, vpns)
    # . Parse the results
    wrapper.parse_output(args, vpns)

    logger.info(
        "Finished at %s" %
        time.strftime(
            "%a, %d %b %Y %H:%M:%S",
            time.localtime()))

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
