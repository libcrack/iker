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

class Issue(object):
    def __init__(self, title=None, severity=None):
        if title is None or severity is None:
            raise ValueError("Mandatory parameters: title, severity")
        else:
            self.title = title
            self.severity = severity

known_issues = []
known_issues.append(Issue(title="Discoverable IKE service",severity="low"))
known_issues.append(Issue(title="IKE v2 is supported", severity="low"))
known_issues.append(Issue(title="The IKE service could be fingerprinted by analysing the vendor ID (VID) returned",severity="low"))
known_issues.append(Issue(title="The IKE service could be fingerprinted by analysing the responses received",severity="low"))
known_issues.append(Issue(title="The DES encryption algorithm was supported",severity="medium"))
known_issues.append(Issue(title="The MD5 hash algorithm was supported",severity="medium"))
known_issues.append(Issue(title="The weak Diffie-Hellman group MODP-768 was supported",severity="medium"))
known_issues.append(Issue(title="The weak Diffie-Hellman group DH Group 2 was supported",severity="medium"))
known_issues.append(Issue(title="The Aggressive Mode was accepted by the IKE service",severity="medium"))
known_issues.append(Issue(title="The Aggressive Mode transmits group name without encryption",severity="low"))
known_issues.append(Issue(title="Client IDs could be enumerated",severity="medium"))


class IkeScanWrapper(object):
    """
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

    """

    def __init__(self, ikescan_path=None, output=None, delay=0.0):
        """
        Class constructor
            @param ikescan_path: ike-scan excutable absolute path
            @param output: output logfile absolute path
            @param delay: micro seconds between checks attemps
        """
        self.ikescan_path = ikescan_path
        self.output = output
        self.delay = delay

        self.encryption_algorithms = [                         # DES, Triple-DES, AES/128, AES/192, AES/256
                '1', '2', '3', '4', '5', '6',
                '7/128', '7/192', '7/256', '8'
                ]
        self.hash_algorithms = ['1', '2', '3', '4', '5', '6']  # MD5, SHA1
        self.authentication_methods = [                        # PKS, RSA, Hybrid, XAUTH
                '1', '2', '3', '4', '5', '6', '7', '8',
                '64221', '64222', '64223', '64224', '65001',
                '65002', '65003', '65004', '65005', '65006',
                '65007', '65008', '65009', '65010'
                ]
        self.dh_groups = [                                     # Diffie-Hellman 1, 2, 5
                '1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
                '11', '12', '13', '14', '15', '16', '17', '18'
                ]

        self._whereis_ikescan()

    def _whereis_ikescan(self):
        """
        Checks if ike-scan binary is present within $PATH
            @return True if ike-scan was found and False in other case.
        """
        if self.ikescan_path is None:
            for pdir in os.environ.get("PATH").split(os.pathsep):
                ikescan_path = os.path.join(pdir + "ike-scan")
                if os.path.exists(ikescan_path):
                    logger.info("ike-scan located in {0}".format(ikescan_path))
                    self.ikescan_path = ikescan_path
            #if self.ikescan_path is None:
            else:
                raise Exception("Cannot find ike-scan in system PATH")


def self.execve(command):
    """
    Executes a program in a new process.
        @param command: absolute executable path
    """
    # proc = subprocess.Popen(['nohup', '/path/bin.exe'],
    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    error = process.stderr.readlines()
    if len(error) > 0 and "ERROR" in error[0] and "port 500" in error[0]:
        msg = "Port already binded. Is another instance of ike-scan running?."
        logger.fatal(msg)
        raise Exception(msg)
    else:
        return process


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


def discovery(args, targets, vpns):
    """
    Run ike-scan to discover IKE services and update the vpns variable with the information found.
        @param args The command line parameters
        @param targets The targets specified (IPs and/or networks)
        @param vpns A dictionary to store all the information
    """
    logger.info("Discovering IKE services, please wait")

    for target in targets:
        process = self.execve("%s -M %s" % (self.ikescan_path, target))
        process.wait()
        ip = None
        info = ""
        for line in process.stdout.readlines():
            if not line.split() \
                    or "Starting ike-scan" in line \
                    or "Ending ike-scan" in line:
                continue
            if line[0].isdigit():
                if info:
                    vpns[ip] = {}
                    vpns[ip]["handshake"] = info.strip()
                    logger.info("IKE service identified at: {0}".format(ip))
                    logger.debug(info)

                ip = line.split()[0]
                info = line
            else:
                info = info + line
        if info and ip not in vpns.keys():
            vpns[ip] = {}
            vpns[ip]["handshake"] = info.strip()
            logger.info("IKE service identified at: {0}".format(ip))
            logger.debug(info)


def check_ike_v2(args, targets, vpns):
    """This method checks if IKE version 2 is supported.
    @param args The command line parameters
    @param vpns A dictionary to store all the information"""

    logger.info("Checking for IKE version 2 support")
    ips = []

    try:
        # Check the IKE v2 support
        for target in targets:

            process = self.execve("%s -2 -M %s" % (self.ikescan_path, target))
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

            process = self.execve(
                "%s --showbackoff %s %s" %
                (self.ikescan_path,
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
        top = len(encryption_algorithms) * len(hash_algorithms) * len(authentication_methods) * len(dh_groups)
        current = 0
        for ip in vpns.keys():

            logger.info("Looking for accepted transforms at %s" % ip)
            vpns[ip]["transforms"] = []

            for enc in encryption_algorithms:
                for hsh in hash_algorithms:
                    for auth in authentication_methods:
                        for group in dh_groups:

                            process = self.execve(
                                "%s -M --trans=%s,%s,%s,%s %s" %
                                (self.ikescan_path, enc, hsh, auth, group, ip))
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
        top = len(encryption_algorithms) * len(hash_algorithms) * len(authentication_methods) * len(dh_groups)
        current = 0
        for ip in vpns.keys():

            logger.info(
                "Looking for accepted transforms in aggressive mode at %s" %
                ip)
            vpns[ip]["aggressive"] = []

            for enc in encryption_algorithms:
                for hsh in hash_algorithms:
                    for auth in authentication_methods:
                        for group in dh_groups:
                            process = self.execve(
                                "%s -M --aggressive -P%s_handshake.txt --trans=%s,%s,%s,%s %s" %
                                (self.ikescan_path, ip, enc, hsh, auth, group, ip))
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
    process = self.execve(
        "%s --aggressive --trans=%s --id=badgroupiker573629 %s" %
        (self.ikescan_path, vpns[ip]["aggressive"][0][0], ip))
    process.wait()
    possible = True
    for line in process.stdout.readlines():
        if "dead peer" in line.lower():
            possible = False
            break
    if possible:
        time.sleep(self.delay/1000.0)
        try:
            fdict = open(args.clientids, "r")
            cnt = 0

            for cid in fdict:
                cid = cid.strip()

                process = self.execve(
                    "%s --aggressive --trans=%s --id=%s %s" %
                    (self.ikescan_path, vpns[ip]["aggressive"][0][0], cid, ip))
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
                time.sleep(self.delay/1000.0)
                # Re-check the same CID if it looked valid
                if enc:
                    process = self.execve(
                        "%s --aggressive --trans=%s --id=%s %s" %
                        (self.ikescan_path, vpns[ip]["aggressive"][0][0], cid, ip))
                    process.wait()

                    enc = False
                    for line in process.stdout.readlines():
                        if "dead peer" in line.lower():
                            vpns[ip]["clientids"].append(cid)
                            logger.info(
                                "\033[92m[*]\033[0m A potential valid client ID was found: %s" %
                                cid)
                            break
                    time.sleep(self.delay/1000.0)
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
        process = self.execve(
            "%s --aggressive --trans=%s --id=badgroupiker123456 %s" %
            (self.ikescan_path, vpns[ip]["aggressive"][0][0], ip))
        process.wait()
        message1 = re.sub(
            r'(HDR=\()[^\)]*(\))',
            r'\1xxxxxxxxxxx\2',
            process.stdout.readlines()[1].strip())
        time.sleep(self.delay/1000.0)

        process = self.execve(
            "%s --aggressive --trans=%s --id=badgroupiker654321 %s" %
            (self.ikescan_path, vpns[ip]["aggressive"][0][0], ip))
        process.wait()
        message2 = re.sub(
            r'(HDR=\()[^\)]*(\))',
            r'\1xxxxxxxxxxx\2',
            process.stdout.readlines()[1].strip())
        time.sleep(self.delay/1000.0)

        process = self.execve(
            "%s --aggressive --trans=%s --id=badgroupiker935831 %s" %
            (self.ikescan_path, vpns[ip]["aggressive"][0][0], ip))
        process.wait()
        message3 = re.sub(
            r'(HDR=\()[^\)]*(\))',
            r'\1xxxxxxxxxxx\2',
            process.stdout.readlines()[1].strip())
        time.sleep(self.delay/1000.0)

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
                process = self.execve(
                    "%s --aggressive --trans=%s --id=%s %s" %
                    (self.ikescan_path, vpns[ip]["aggressive"][0][0], cid, ip))
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
                time.sleep(self.delay/1000.0)
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
    pathxml = self.output
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
        logger.info("%s" % FLAWVPNDISCOVERABLE)

        try:
            fxml.write(
                "\t\t\t<flaw flawid=\"1\" description=\"%s\"><![CDATA[%s]]></flaw>\n" %
                (FLAWVPNDISCOVERABLE, vpns[ip]["handshake"]))
        except:
            pass

        # IKE v2
        if "v2" in vpns[ip].keys() and vpns[ip]["v2"]:
            logger.info("%s" % FLAWIKEV2SUPPORTED)
            try:
                fxml.write(
                    "\t\t\t<flaw flawid=\"10\" description=\"%s\"></flaw>\n" %
                    FLAWIKEV2SUPPORTED)
            except:
                pass

        # Fingerprinted by VID
        if "vid" in vpns[ip].keys() and len(vpns[ip]["vid"]) > 0:
            logger.info("%s" % FLAWVPNFINGVID)
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
                (FLAWVPNFINGBACKOFF, vpns[ip]["showbackoff"]))
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
                        logger.info("%s" % FLAWWEAKENCALG)
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
                        logger.info("%s" % FLAWWEAKHASHALG)
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
                        logger.info("%s" % FLAWWEAKDHGALG)
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
                        logger.info("%s" % FLAWWEAKDH2GALG)
                    logger.debug("%s" % trio[2])
                    try:
                        fxml.write(
                            "\t\t\t<flaw flawid=\"6\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" %
                            (FLAWWEAKDH2GALG, trio[1], trio[2]))
                    except:
                        pass

        # Aggressive Mode ?
        if "aggressive" in vpns[ip].keys() and len(vpns[ip]["aggressive"]) > 0:
            logger.info("%s" % FLAWAGGRESSIVE)
            for trio in vpns[ip]["aggressive"]:
                logger.info("\t%s" % (trio[1]))
                logger.debug("%s" % (trio[2]))
                try:
                    fxml.write(
                        "\t\t\t<flaw flawid=\"7\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" %
                        (FLAWAGGRESSIVE, trio[1], trio[2]))
                except:
                    pass
            logger.info("%s" % FLAWAGGRGROUPNOENC)
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
                (FLAWCIDENUMERATION,
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


def main(argv=sys.argv[1:]):

    if os.geteuid():
        logger.fatal("\033[91m[*]\033[0m got r00t?")
        return 10

    banner()
    vpns = {}
    args, targets = get_arguments()

    ike_scan_wrapper = IkeScanWrapper(output=args.output)

    logger.info("Starting at %s" % time.strftime(
            "%a, %d %b %Y %H:%M:%S",time.localtime()))

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

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
