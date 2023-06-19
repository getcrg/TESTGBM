"""
Creator:    Walter J. Solano Vindas
            CCIE #55772 / CCNP DevNet
            wsolano@getcrg.com
Script to change SNMP setting in multiple devices by reading the list of devices from a CSV file
The script recognize between different vendors based on the information in the CSV,
so it knows which commands to send. Current supported manufactures Cisco, Juniper
"""

import datetime
import logging
import os as operativesystem
from datetime import datetime
from logging.config import fileConfig

import pandas as pd

import crg_helper
import cwc_add
import cwc_cisco
import cwc_cisco_sg300
import cwc_fortinet
import cwc_juniper


# --------------------------------------------------------------------------


def safe_crf(logger, dev_info, cmds, hostname, net_connect):
    """

    Parameters
    ----------
    logger :
    dev_info :
    net_connect :

    Returns
    -------

    """
    logger.info(f'{dev_info["IP"]}:Saving configuration changes')
    net_connect.send_config_set(cmds["save_cfg"])
    logger.info(f'{dev_info["IP"]}:Configuration saved')
    logger.info(f'{dev_info["IP"]}:Saving configuration to file')
    crg_helper.command_to_file(hostname, cmds["sh_run_cmd"], net_connect, logger, dev_info["IP"])


# --------------------------------------------------------------------------


def update_configs(config_dict, logger, ip_dict, current_path):
    """
    :param config_dict:
    :param logger:
    :param ip_dict:
    :param current_path:
    :return:
    """
    # list where information will be stored
    device_data = []

    for ips in ip_dict[config_dict["csv_ip_colum"]]:
        dev_info = {key: ip_dict[key][ips] for key in ip_dict.keys()}
        device_type, ssh_port = crg_helper.autodetect_ssh(dev_info["IP"],
                                                          config_dict["username"],
                                                          config_dict["password"],
                                                          logger, config_dict)

        if device_type != 'NA':
            device_connection_details = {
                'device_type': device_type,
                'ip': dev_info["IP"],
                'port': ssh_port,
                'username': config_dict["username"],  # ssh username
                'password': config_dict["password"],  # ssh password
                'secret': config_dict["password"],  # ssh_enable_password
                'ssh_strict': False,
                'fast_cli': False,
                'banner_timeout': 50,
            }

            # connecting to device
            logger.info(f'{dev_info["IP"]}:'
                        f'Creating SSH session to device')
            net_connect = crg_helper.connect_to_device(device_connection_details, logger)
            if net_connect is False:
                logger.error(f'{dev_info["IP"]}:Failure to connect to device')
                continue
            ssh_connection = True

            match device_type:
                case 'cisco_ios':
                    cmds = crg_helper.config_parser(logger, 'cisco_commands')
                    multi_link = cwc_cisco.multilink_chk(logger, dev_info, net_connect)
                    vrf_lst = cwc_cisco.vrf_chk(logger, multi_link, dev_info, net_connect)
                    vrf = vrf_lst

                    logger.info(f'{dev_info["IP"]}:Getting device details')
                    hostname, os_version, device_model, uptime, serial, memory = \
                        cwc_cisco.device_info(
                            logger,
                            dev_info,
                            net_connect)
                    logger.info(f'{dev_info["IP"]}:hostname {hostname}, OS version {os_version},'
                                f'Model {device_model}, Uptime {uptime} Serial # {serial}, '
                                f'Memory {memory}')

                    logger.info(f'{dev_info["IP"]}:Saving device information to file')
                    crg_helper.command_to_file(hostname, cmds["sh_os_cmd"], net_connect, logger,
                                               dev_info["IP"])

                    logger.info(f'{dev_info["IP"]}:Saving device configuration to file')
                    crg_helper.command_to_file(hostname, cmds["sh_run_cmd"], net_connect, logger,
                                               dev_info["IP"])

                    snmp_acl = cwc_cisco.snmp_acl(logger, dev_info, net_connect)
                    snmp_enable = cwc_cisco.enable_snmp(logger, dev_info, net_connect)

                    snmp_community = cwc_cisco.snmp(logger, dev_info, net_connect, vrf_lst)
                    remote_access = cwc_cisco.rmt_access(logger, dev_info, net_connect)
                    static_routes = 'NA'
                    other_update = 'NA'

                    if remote_access or snmp_community or snmp_acl == 'yes':
                        safe_crf(logger, dev_info, cmds, dev_info['NAME'], net_connect)
                        net_connect.disconnect()
                    else:
                        logging.warning(
                            '%s:No modifications performed, no need to save configuration',
                            dev_info["IP"])
                    solar_winds = cwc_add.add_devs(logger, dev_info, config_dict,
                                                   {"ManuFacture": "cisco",
                                                    "MachineType": "Router",
                                                    "vrf": vrf_lst},
                                                   ssh_port, multi_link)
                    if net_connect: net_connect.disconnect()
                case 'juniper_junos':
                    cmds = crg_helper.config_parser(logger, 'juniper_commands')
                    multi_link, ip_add_list = cwc_juniper.multilink_chk(logger, dev_info,
                                                                        net_connect)
                    routing_instance_lst = cwc_juniper.routing_instance_chk(logger, multi_link,
                                                                            dev_info, net_connect)

                    logger.info(f'{dev_info["IP"]}:Getting device details')
                    hostname, os_version, device_model, uptime, serial, memory = cwc_juniper.device_info(
                        logger,
                        dev_info,
                        net_connect)
                    logger.info(
                        f'{dev_info["IP"]}:Hostname {hostname}, OS version {os_version}, Model {device_model}, '
                        f'Uptime {uptime} Serial # {serial}, Memory {memory}')

                    logger.info(f'{dev_info["IP"]}:Saving device information to file')
                    crg_helper.command_to_file(hostname, cmds["sh_os_cmd"], net_connect, logger,
                                               dev_info["IP"])

                    logger.info(f'{dev_info["IP"]}:Saving device configuration to file')
                    crg_helper.command_to_file(hostname, cmds["sh_run_cmd"], net_connect, logger,
                                               dev_info["IP"])

                    logger.info(f'{dev_info["IP"]}:Cleanning uncomited configurations')
                    net_connect.config_mode()
                    net_connect.send_command("rollback 0")

                    if len(multi_link) > 1 and len(routing_instance_lst) == 1:
                        static_routes = cwc_juniper.static_routes_update(logger, dev_info,
                                                                         net_connect)
                    if len(multi_link) > 1 and len(routing_instance_lst) > 1:
                        static_routes = 'NA'
                    if len(multi_link) == 1 and len(
                            routing_instance_lst) == 1 and 'NA' not in routing_instance_lst:
                        static_routes = 'NA'
                    if len(routing_instance_lst) == 1:
                        static_routes = cwc_juniper.static_routes_update(logger, dev_info,
                                                                         net_connect)

                    term_chk, policy_statement_name = cwc_juniper.term_chk(logger, dev_info,
                                                                           net_connect)
                    if term_chk is True:
                        other_update = cwc_juniper.term_update(logger, dev_info,
                                                               policy_statement_name, net_connect)
                    else:
                        other_update = 'NA'

                    snmp_community = cwc_juniper.snmp(logger, routing_instance_lst, multi_link,
                                                      dev_info, net_connect)
                    snmp_enable = bool(snmp_community)
                    remote_access = cwc_juniper.rmt_access(logger, dev_info, net_connect)
                    snmp_acl = cwc_juniper.snmp_acl(logger, routing_instance_lst, dev_info,
                                                    net_connect)
                    net_connect.exit_config_mode()
                    vrf = routing_instance_lst

                    if remote_access or snmp_community or snmp_acl == 'yes':
                        safe_crf(logger, dev_info, cmds, hostname, net_connect)
                        net_connect.disconnect()
                    else:
                        logging.warning(
                            '%s:No modifications performed, no need to save configuration',
                            dev_info["IP"])
                    solar_winds = cwc_add.add_devs(logger, dev_info, config_dict,
                                                   {"ManuFacture": "juniper",
                                                    "MachineType": "Router",
                                                    "vrf": routing_instance_lst,
                                                    "interfaces": multi_link,
                                                    'ip_address': ip_add_list},
                                                   ssh_port, multi_link)

                case 'fortinet':
                    cmds = crg_helper.config_parser(logger, 'fortinet_commands')

                    vdom = cwc_fortinet.vdom_chk(logger, dev_info, net_connect)
                    multi_link, ip_address_list = cwc_fortinet.multilink_chk(logger, dev_info,
                                                                             net_connect, vdom)

                    logger.info(f'{dev_info["IP"]}:'
                                f'Getting device details')
                    hostname, os_version, device_model, uptime, serial, memory = \
                        cwc_fortinet.device_info(
                            logger,
                            dev_info,
                            net_connect, vdom)
                    logger.info(f'{dev_info["IP"]}:'
                                f'Hostname {hostname}, OS version {os_version}, '
                                f'Model {device_model}, Uptime {uptime}'
                                f'Serial # {serial}, Memory {memory}')
                    logger.info(f'{dev_info["IP"]}:'
                                f'Saving device information to file')
                    crg_helper.command_to_file(hostname, cmds["sh_os_cmd"], net_connect, logger,
                                               dev_info["IP"])

                    logger.info(f'{dev_info["IP"]}:'
                                f'Saving device configuration to file')
                    crg_helper.command_to_file(hostname, cmds["sh_run_cmd"], net_connect, logger,
                                               dev_info["IP"])

                    snmp_enable = \
                        cwc_fortinet.enable_snmp(logger, dev_info, net_connect,
                                                 vdom)

                    snmp_community = \
                        cwc_fortinet.snmp(logger, dev_info, net_connect, vdom)

                    static_routes = cwc_fortinet.static_routes_update(logger, dev_info,
                                                                      net_connect, vdom, multi_link)
                    remote_access = 'NA'
                    snmp_acl = 'NA'
                    other_update = 'NA'
                    vrf = 'NA'
                    if len(multi_link) > 1:
                        other_update = cwc_fortinet.vrf_creation(logger, dev_info,
                                                                 net_connect, vdom, multi_link)
                    net_connect.disconnect()
                    solar_winds = cwc_add.add_devs(logger, dev_info, config_dict,
                                                   {"ManuFacture": "fortigate",
                                                    "MachineType": "Router",
                                                    "vrf": vrf},
                                                   ssh_port, multi_link)
                    if other_update:
                        vrf = '10'
                case 'cisco_sg300':
                    cmds = crg_helper.config_parser(logger, 'cisco_sg_cmds')

                    logger.info(f'{dev_info["IP"]}:'
                                f'Getting device details')
                    hostname, os_version, device_model, uptime, serial, memory = \
                        cwc_cisco_sg300.device_info(
                            logger,
                            config_dict,
                            ip_dict, ips,
                            net_connect)
                    logger.info(f'{dev_info["IP"]}:'
                                f'hostname {hostname}, OS version {os_version}, '
                                f'Model {device_model}, Uptime {uptime},'
                                f'Serial # {serial}, Memory {memory}')
                    logger.info(f'{dev_info["IP"]}:'
                                f'Saving device information to file')
                    crg_helper.command_to_file(hostname, cmds["sh_os_cmd"],
                                               net_connect, logger, ips)

                    logger.info(f'{dev_info["IP"]}:'
                                f'Saving device configuration to file')
                    crg_helper.command_to_file(hostname, cmds["sh_run_cmd"],
                                               net_connect, logger, ips)

                    remote_access = \
                        cwc_cisco_sg300.rmt_access(logger, dev_info, net_connect)
                    snmp_acl = \
                        cwc_cisco_sg300.snmp_acl(logger, dev_info, net_connect)
                    snmp_community = True
                    vrf = 'NA'
                    other_update = 'NA'

            device_data.append(
                [dev_info["IP"], hostname, ssh_connection, snmp_enable, snmp_community, snmp_acl,
                 remote_access, static_routes, solar_winds, other_update, os_version, device_model,
                 uptime, serial, memory, vrf])


        else:
            logger.warning(f'{dev_info["IP"]}:Device login issue, '
                           f'continuing with next device')
            ssh_connection = False
            device_data.append(
                [dev_info["IP"], ssh_connection, 'NA', 'NA', 'NA',
                 'NA', 'NA', 'NA', 'NA', 'NA', 'NA', 'NA', 'NA', 'NA', 'NA'])
        # df2 = pd.DataFrame.from_dict(ip_dict)
        # device_info = df2.loc[ips]

    # dumping device information dict to csv file
    valid_path = operativesystem.path.exists(f'{current_path}//outputs//reports')

    if not valid_path:
        logger.info(f'Creating folder to store reports {current_path}')
        operativesystem.makedirs(f'{current_path}//outputs//reports')
    logger.info(f'Folder to store reports already exist {current_path}')
    date_and_time = datetime.now().strftime('%m_%d_%Y_%H_%M_%S')
    filename = f'{current_path}//outputs//reports//snmp_update_solarwinds_{date_and_time}.csv'
    logger.info(f'Saving all device information to file {filename}')
    data_frame = pd.DataFrame(device_data)
    data_frame.columns = ['IP Address', 'Hostname', 'SSH Connection', 'SNMP Enable',
                          'SNMP Community Updated', 'SNMP ACL Updated', 'Remote Access Updated',
                          'Static Routes', 'SolarWinds', 'Other Update', 'OS Version',
                          'Device Model',
                          'Up time', 'Serial Number', 'Memory', 'VRF']

    data_frame.to_csv(filename)


# --------------------------------------------------------------------------


def main():
    """
    :return:
    """
    fileConfig('logging.ini')
    logger = logging.getLogger('dev')

    config_dict = crg_helper.config_parser(logger, 'config')

    current_path = operativesystem.getcwd()
    filename = f'{current_path}/inputs/{config_dict["inventory_file"]}'
    ip_df = pd.read_csv(filename)
    ip_dict = pd.DataFrame.to_dict(ip_df)
    logger.debug('Creating dataframe with IP information from %s', filename)
    logger.debug('About to start connecting to the devices')

    update_configs(config_dict, logger, ip_dict, current_path)


if __name__ == "__main__":
    main()
