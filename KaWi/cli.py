import os
import re
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scapy'))
from scapy.all import *  # noqa: E402
from scapy.consts import LINUX, WINDOWS

import sniff


def initial_setup():
    def input_check_iface_num(prompt: str):
        while True:
            try:
                user_input = int(input(prompt))
                if user_input in range(1, len(sniff.iface_list)):
                    return user_input
                print('(E) Invalid interface number.')
            except ValueError:
                print('(E) Invalid interface number.')

    print('*First, specify the two network interface to use: [managed], [monitor].')
    print('*Your network interfaces:')
    iface_list = sniff.lookup_iface()

    for idx in range(len(sniff.iface_list)):
        iface = sniff.iface_list[idx]
        print(f'[{idx}] name:\'{iface.name}\'   description:\'{iface.description}\' MAC:{iface.mac}')

    if LINUX:
        user_input1 = input_check_iface_num('[managed & monitor]: ')
        user_input2 = None
    else:
        user_input1 = input_check_iface_num("[managed]: ")
        user_input2 = input_check_iface_num("[monitor]: ")

    sniff.set_two_ifaces_to_use(user_input1, user_input2, iface_list)
    print("*Setup was successful.")


def show_commands():
    print("*List of command numbers:")
    print("\t[00] Reset network interface to use")
    print("\t[01] List nearby WiFi networks")
    print("\t[02] Collect IP and MAC addresses of all hosts(AP and client)")
    print("\t(not perfect)[10] Send deauth frames(force disconnect the target client from the network)")
    print("\t(not yet supported)[11] Create a Rogue AP")
    print("\t(not yet supported)[20] Test KRACK - 4-way handshake reinstall PTK-TK(used to encrypt data frames)")
    print(
        "\t(not yet supported)[21] Test KRACK - 4-way handshake reinstall GTK(used to encrypt broadcast and multicast frames)")
    print(
        "\t(not yet supported)[22] Test KRACK - 4-way handshake reinstall IGTK(used to encrypt broadcast and multicast frames)")
    # print("[21] Test KRACK - group key handshake reinstall GTK(used to encrypt broadcast and multicast frames)")
    # print("[22] Test KRACK - group way handshake reinstall IGTK(used to encrypt broadcast and multicast frames)")


def handle_command(command):
    commands = command.split()
    command_num = int(commands[0]) if commands[0].isdecimal() else -1
    if command_num == 0:
        initial_setup()
    elif command_num == 1:
        sniff.network_list = sniff.scan_AP(frequency='2.4ghz')
        sniff.connected_network = next(
            (network for network in sniff.network_list if network.bssid == sniff.get_connected_wifi_bssid()), None)
        print("*Network information you are connected to:")
        print(sniff.connected_network)
    elif command_num == 2:
        sniff.host_list = sniff.scan_host()
    elif command_num == 10:
        bssid, channel = None, None

        if len(commands) < 2:
            print('*Requires option: target IP or MAC address')
            return
        try:
            client_mac = [host.MAC for host in sniff.host_list if host.IP == commands[1] or host.MAC == commands[1]][0]
        except (TypeError, IndexError) as e:
            client_mac = commands[1]
        if len(commands) == 4:
            bssid = commands[2]
            channel = int(commands[3])
        sniff.disconnect_client(client_MAC=client_mac, bssid=bssid, channel=channel)
    else:
        print("*Invalid command.\n")
        show_commands()


def print_welcome_message():
    welcome_message = r"""
----------------------------------------------------
     _  __   __        ___ 
    | |/ /__ \ \      / (_)
    | ' // _` \ \ /\ / /| |
    | . \ (_| |\ V  V / | |
    |_|\_\__,_| \_/\_/  |_|
    (Simple prototype CLI for Wi-Fi analysis tool)
----------------------------------------------------
----------------------------------------------------
    """
    print(welcome_message)


if __name__ == '__main__':

    initial_setup()
    print_welcome_message()
    show_commands()
    while True:
        try:
            user_input = input(">> ")
            if user_input == "exit":
                break
            if len(user_input) > 0:
                handle_command(user_input)
        except KeyboardInterrupt:
            continue
