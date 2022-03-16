#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Copyright (c) 2013-2022, SMARTX
# All rights reserved.
import ConfigParser
import logging
import os
import platform
import subprocess
import sys
import textwrap
from time import sleep


X86_VERSION_MAP = {
    "2.6": "2.6",
    "3.0": "2.6",
    "3.2": "3.0",
    "3.4": "3.2",
    "3.6": "3.4",
    "4.0": "3.6",
    "4.2": "4.0",
    "4.4": "4.2",
    "5.0": "4.4",
}

AARCH64_VERSION_MAP = {
    "3.2": "3.2",
    "3.4": "3.2",
    "3.6": "3.4",
    "4.0": "3.6",
    "4.2": "4.0",
    "4.4": "4.2",
    "5.0": "4.4",
}

STATE_PRIMARY = "PRIMARY"
STATE_SECONDARY = "SECONDARY"
INVENTORY_IP_ATTACHMENT = "ansible_ssh_user=smartx ansible_ssh_private_key_file=/home/smartx/.ssh/smartx_id_rsa"

action_dict = {}


def register_action(func):
    action_dict[func.__name__] = func
    return func


def get_current_data_ip():
    parser = ConfigParser.SafeConfigParser()
    parser.read("/etc/zbs/zbs.conf")
    return parser.get("network", "data_ip")


def get_mongo_image_name():
    cmd = "podman images localhost/mongodb-base --format '{{.Repository}}:{{.Tag}}'"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        msg = "podman query mongo images failed, rc: {} stdout: {} stderr: {}"
        logging.error(msg.format(process.returncode, stdout, stderr))
        return []

    res = []
    for line in stdout.split("\n"):
        if line.strip():
            res.append(line.strip())
    return res


def get_container_id():
    cmd = "podman ps | grep localhost/mongodb-base | awk '{print $1}'"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        msg = "podman query mongo container failed, rc: {} stdout: {} stderr: {}"
        logging.error(msg.format(process.returncode, stdout, stderr))
        return []
    container_id = stdout.strip()
    return container_id

def get_mongo_db_version(mongo_ip):
    cmd = 'mongo --host {} --quiet --norc --eval "db.version()"'.format(mongo_ip)
    container_id = get_container_id()
    if container_id:
        cmd = "podman exec -it {} ".format(container_id) + cmd

    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        msg = "get mongo {} db.version failed, stdout: {} stderr: {} rc: {}"
        logging.info(msg.format(mongo_ip, stdout, stderr, process.returncode))
        return ""

    return stdout.strip()


def get_mongo_rs_status(with_db_version=True):
    cmd = textwrap.dedent(
        """
        mongo --quiet --norc --eval "rs.status().members.forEach(function(i){ print(i.name + '@' + i.stateStr) })"
        """
    ).strip()
    container_id = get_container_id()
    if container_id:
        cmd = "podman exec -it {} ".format(image_name[0]) + cmd

    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        msg = "get mongo rs.status failed, stdout: {} stderr: {} rc: {}"
        logging.info(msg.format(stdout, stderr, process.returncode))
        return []

    res = []
    for line in stdout.strip().split("\n"):
        mongo_ip_port, state_str = line.strip().split("@")
        mongo_ip, _ = mongo_ip_port.split(":")
        db_version = get_mongo_db_version(mongo_ip) if with_db_version else ""
        res.append(
            {
                "mongo_ip": mongo_ip,
                "state": state_str,
                "db_version": db_version,
            }
        )
    return res


def step_down_mongo_primary(mongo_ip):
    """
    see https://docs.mongodb.com/manual/reference/method/rs.stepDown/#client-connections
    Because the disconnect includes the connection used to run the method,
    you cannot retrieve the return status of the method if the method completes successfully.
    You can only retrieve the return status of the method if it errors.
    """
    cmd = "mongo --host {} --norc --eval 'rs.stepDown()'".format(mongo_ip)
    container_id = get_container_id()
    if container_id:
        cmd = "podman exec -it {} ".format(image_name[0]) + cmd

    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:  # expected result before mongo v4.2
        return False
    return True


def set_compatibility_version(data_ip, version):
    cmd = "mongo --host {} --quiet --norc --eval ".format(data_ip)
    container_id = get_container_id()
    if container_id:
        cmd = "podman run --rm -it --network host {} ".format(image_name[0]) + cmd

    exec_cmd = cmd + '"db.adminCommand( { setFeatureCompatibilityVersion:' + "'{}'".format(version) + '} )"'
    process = subprocess.Popen(exec_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        msg = "setFeatureCompatibilityVersion failed on mongo {}, stdout: {} stderr: {} rc: {}"
        logging.info(msg.format(data_ip, stderr, process.returncode))
        return False

    _eval = '"db.adminCommand({ getParameter: 1, featureCompatibilityVersion: 1 }).featureCompatibilityVersion"'
    exec_cmd = cmd + _eval
    process = subprocess.Popen(exec_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        msg = "query featureCompatibilityVersion failed on mongo {}, stdout: {} stderr: {} rc: {}"
        logging.info(msg.format(data_ip, stderr, process.returncode))
        return False

    if version not in stdout:
        logging.error("Expected featureCompatibilityVersion {}, actually get {}".format(version, stdout.strip()))
        return False

    return True


@register_action
def cmd_get_mongo_list(*args):
    mongo_list = get_mongo_rs_status(with_db_version=False)
    if not mongo_list:
        logging.error("Failed to get mongo rs.status()")
        return False

    print(" ".join([item["mongo_ip"] for item in mongo_list]))
    return True


@register_action
def gen_mongo_cluster_inventory(*args):
    mongo_list = get_mongo_rs_status(with_db_version=False)
    if not mongo_list:
        logging.error("Failed to get mongo rs.status()")
        return False

    witness = []
    if os.path.exists("/etc/zbs/witness"):
        with open("/etc/zbs/witness", "rt") as f:
            witness_ip_port = f.read().strip().split(":")[0]
            if witness_ip_port and witness_ip_port[0]:
                witness.append(witness_ip_port[0])

    conf_str = "[mongo_cluster]\n"
    for item in mongo_list:
        conf_str += "{} {}\n".format(item["mongo_ip"], INVENTORY_IP_ATTACHMENT)

    conf_str += "[witness]\n"
    for item in witness:
        conf_str += "{} {}\n".format(item, INVENTORY_IP_ATTACHMENT)

    conf_str += "[current_node]\n"
    conf_str += "{} {}\n".format(get_current_data_ip(), INVENTORY_IP_ATTACHMENT)

    with open(os.path.join(os.getcwd(), "mongo_cluster_inventory"), "w") as f:
        f.write(conf_str)
    return True


@register_action
def cmd_get_upgrade_road_map(*args):
    version_map = {
        "x86_64": X86_VERSION_MAP,
        "aarch64": AARCH64_VERSION_MAP,
    }.get(platform.machine())
    full_version_list = sorted(version_map.keys())

    mongo_list = get_mongo_rs_status()
    if not mongo_list:
        logging.error("Failed to get mongo rs.status() and db.version()")
        return False

    cluster_versions = []
    for item in mongo_list:
        if item.get("db_version"):
            cluster_versions.append(item["db_version"][:3])
        else:
            logging.error("Failed to get db.version() from {}".format(item["mongo_ip"]))
            return False

    start_version = min(cluster_versions)
    print(" ".join(sorted(item for item in full_version_list if item > start_version)))
    return True


@register_action
def gen_new_mongo_conf(*args):
    conf_str = textwrap.dedent(
        """
        systemLog:
          path: /var/log/mongodb/mongod.log
          destination: file
          logAppend: true
          logRotate: reopen
        storage:
          dbPath: /var/lib/mongodb
          journal:
            enabled: true
        processManagement:
           fork: false
        net:
          bindIp: 127.0.0.1,{}
          port: 27017
          maxIncomingConnections: 64000
        replication:
          oplogSizeMB: 4096
          replSetName: zbs
        """
    )
    with open("/etc/mongod.conf", "w") as f:
        f.write(conf_str.format(get_current_data_ip()).strip() + "\n")
    return True


def _check_cluster_version(next_v, mongo_list):
    version_map = {
        "x86_64": X86_VERSION_MAP,
        "aarch64": AARCH64_VERSION_MAP,
    }.get(platform.machine())
    if next_v not in version_map:
        logging.error("not support upgrade for target version: {}".format(next_v))
        return False

    if len(mongo_list) not in [3, 5]:
        logging.error("The number of cluster nodes needs to be 3 or 5.")
        return False

    v = version_map.get(next_v)
    pre_v = version_map.get(v)
    mongodb_versions = sorted(item["db_version"][:3] for item in mongo_list)
    if len(set(mongodb_versions)) not in [1, 2]:
        logging.error("Please upgrade all {} to {} before upgrade to {}".format(mongodb_versions, v, next_v))
        return False

    if pre_v != v and pre_v in mongodb_versions:
        if mongodb_versions in [[pre_v, v, v], [pre_v, v, v, v, v]]:
            return True
        else:
            logging.error("Please upgrade all {} to {} before upgrade to {}".format(mongodb_versions, v, next_v))
            return False

    abnormal_versions = [item for item in mongodb_versions if item not in {v, next_v}]
    if abnormal_versions:
        logging.error("Please upgrade all {} to {} before upgrade to {}".format(abnormal_versions, v, next_v))
        return False

    return True


@register_action
def loop_check_for(target_version, *args):
    for r in range(120):
        logging.info("check mongo rs.status(), round {}".format(r))
        mongo_list = get_mongo_rs_status()
        if not mongo_list:
            sleep(10)
            continue

        full_info = True
        for item in mongo_list:
            logging.info("{} {} {}".format(item["mongo_ip"], item["db_version"], item["state"]))
            if not (item["mongo_ip"] and item["db_version"] and item["state"]):
                full_info = False

        if not full_info:
            logging.info("Incomplete access to rs.status() and db.version(), wait ...")
            sleep(10)
            continue

        if not _check_cluster_version(target_version, mongo_list):
            logging.info("Current cluster version does not support upgrading to {}".format(target_version))
            return False

        primary = [item for item in mongo_list if item["state"] == STATE_PRIMARY]
        if not primary:
            logging.info("Mongo PRIMARY not FOUND, wait for PRIMARY ...")
            sleep(10)
            continue

        abnormal = [item["state"] for item in mongo_list if item["state"] not in [STATE_PRIMARY, STATE_SECONDARY]]
        if abnormal:
            logging.info("wait for abnormal states: {} ...".format(abnormal))
            sleep(10)
            continue

        return True

    logging.info("check mongo rs.status() timeout, please check mongo cluster status.")
    return False


@register_action
def check_mongo_cluster_states(*args):
    mongo_list = get_mongo_rs_status()
    if not mongo_list:
        logging.error("Failed to get mongo rs.status()")
        return False

    for item in mongo_list:
        logging.info("{} {} {}".format(item["mongo_ip"], item["db_version"], item["state"]))

    primary = [item for item in mongo_list if item["state"] == STATE_PRIMARY]
    if not primary:
        logging.info("Mongo PRIMARY not FOUND, wait for PRIMARY ...")
        return False

    abnormal = [item["state"] for item in mongo_list if item["state"] not in [STATE_PRIMARY, STATE_SECONDARY]]
    if abnormal:
        logging.info("Wait for abnormal states: {} ...".format(abnormal))
        return False
    return True


@register_action
def gen_plan_inventory(next_v, *args):
    version_map = {
        "x86_64": X86_VERSION_MAP,
        "aarch64": AARCH64_VERSION_MAP,
    }.get(platform.machine())
    if next_v not in version_map:
        logging.error("not support upgrade for target version: {}".format(next_v))
        return False

    v = version_map.get(next_v)
    # pre_v = version_map.get(v)
    latest_v = sorted(version_map.keys())[-1]

    mongo_list = get_mongo_rs_status()
    if not mongo_list:
        logging.error("Failed to get mongo rs.status() and db.version()")
        return False
    for item in mongo_list:
        if not item.get("db_version"):
            logging.error("Failed to get db.version() from {}".format(item["mongo_ip"]))
            return False

    mongo_primary = [item for item in mongo_list if item["state"] == STATE_PRIMARY]
    if not mongo_primary:
        logging.error("mongo PRIMARY not found.")
        return False

    node_to_up = [item for item in mongo_list if item["db_version"][:3] != next_v]
    secondary_to_upgrade = [item for item in node_to_up if item["state"] == STATE_SECONDARY]
    primary_to_upgrade = [item for item in node_to_up if item["state"] == STATE_PRIMARY]

    conf_str = "[secondary_to_upgrade]\n"
    for item in secondary_to_upgrade:
        conf_str += "{} {}\n".format(item["mongo_ip"], INVENTORY_IP_ATTACHMENT)
    conf_str += "[primary_to_upgrade]\n"
    for item in primary_to_upgrade:
        conf_str += "{} {}\n".format(item["mongo_ip"], INVENTORY_IP_ATTACHMENT)

    with open(os.path.join(os.getcwd(), "plan_inventory"), "w") as f:
        f.write(conf_str)
    return True


def _step_down_old(next_v):
    version_map = {
        "x86_64": X86_VERSION_MAP,
        "aarch64": AARCH64_VERSION_MAP,
    }.get(platform.machine())
    if next_v not in version_map:
        logging.error("Not support upgrade for target version: {}".format(next_v))
        return False

    mongo_list = get_mongo_rs_status()
    if not mongo_list:
        logging.error("Failed to get mongo rs.status() and db.version()")
        return False
    for item in mongo_list:
        if not item.get("db_version"):
            logging.error("Failed to get db.version() from {}".format(item["mongo_ip"]))
            return False

    v = version_map.get(next_v)
    pre_v = version_map.get(v)
    primary = {item["db_version"][:3]: item for item in mongo_list if item["state"] == STATE_PRIMARY}
    if pre_v != v and pre_v in primary:
        old = primary.get(pre_v)
        msg = "Prepare to Step-Down {} {} {}"
        logging.info(msg.format(old["mongo_ip"], old["db_version"], old["state"]))
        return step_down_mongo_primary(old["mongo_ip"])
    return True


@register_action
def step_down_old_version_primary(next_v, *args):
    # expected false before mongo v4.2
    if _step_down_old(next_v):
        return True

    # wait primary
    primary_ok = False
    for i in range(30):
        logging.info("Wait new primary after Step-Down old version, round {}".format(i))
        sleep(10)
        if check_mongo_cluster_states():
            primary_ok = True
            break

    if not primary_ok:
        return False

    # check again
    return _step_down_old(next_v)


@register_action
def set_compatibility_version_for_upgrade(target_version, *args):
    version_map = {
        "x86_64": X86_VERSION_MAP,
        "aarch64": AARCH64_VERSION_MAP,
    }.get(platform.machine())
    if target_version not in version_map:
        logging.error("not support upgrade for target version: {}".format(target_version))
        return False

    # mongo 3.2 version not support setFeatureCompatibilityVersion
    before_version = version_map.get(target_version)
    if before_version <= "3.2":
        return True

    return set_cluster_compatibility_version(before_version)


@register_action
def set_cluster_compatibility_version(version, *args):
    mongo_list = get_mongo_rs_status(with_db_version=False)
    if not mongo_list:
        logging.error("Failed to get mongo rs.status()")
        return False

    mongo_primary = [item for item in mongo_list if item["state"] == STATE_PRIMARY]
    if not mongo_primary:
        logging.error("mongo PRIMARY not found.")
        return False

    primary_ip = mongo_primary[0]["mongo_ip"]
    return set_compatibility_version(primary_ip, version)


def main():
    action = sys.argv[1]
    args = sys.argv[2:]
    if action not in action_dict:
        logging.error("action {} not found in mongoup.py".format(action))
        sys.exit(1)

    try:
        res = action_dict[action](*args)
    except Exception as e:
        logging.exception(e)
        sys.exit(1)

    if not res:
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    main()
