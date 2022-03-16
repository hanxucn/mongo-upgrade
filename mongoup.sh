#!/bin/bash

cur=$(dirname $(realpath "$0"))
echo "Working under $cur"

mongo_list=($(python $cur/mongoup.py cmd_get_mongo_list))
if [ ! $? -eq 0 ]; then
    echo "Error on getting mongo cluster members with rs.status()"
    exit 1
fi

echo "Check cluster master node remain disk space ..."
for node in "${mongo_list[@]}"; do
    remain=$(ssh -q -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" \
        -i /home/smartx/.ssh/smartx_id_rsa smartx@$node "df /" | tail -n 1 | awk '{print $4}')

    if [[ ! $? -eq 0 ]]; then
        echo "Error on check node $node remain disk space."
        exit 1
    fi
    echo "node $node: $((remain / 1024 / 1024))GiB"
    if [[ $((remain / 1024 / 1024)) -lt 8 ]]; then
        echo "The remaining disk space of node $node is less than 8GiB"
        exit 1
    fi
done

echo "Generating mongo cluster ansible inventory ..."
if ! python $cur/mongoup.py gen_mongo_cluster_inventory; then
    echo "Error on gen_mongo_cluster_inventory."
    exit 1
fi
cat $cur/mongo_cluster_inventory

echo "Sync mongo package to master node and gen new mongo conf ..."
ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i $cur/mongo_cluster_inventory $cur/pre_upgrade.yaml \
    --extra-vars "src_path=$cur dst_path=$(realpath $cur/..)"
if [ ! $? -eq 0 ]; then
    echo "Error on sync package to cluster master node."
    exit 1
fi

if [[ -e /usr/lib/systemd/system/elf-vm-monitor.service ]]; then
    echo "All elf-vm-monitor.service will be stopped during mongo upgrading"
    if ! cluster-upgrade stop_elf_vm_monitor; then
        echo "Error on stopping elf-vm-monitor.service before upgrade mongod."
        exit 1
    fi
fi

echo "Generating mongo upgrade road map ..."
versions=($(python $cur/mongoup.py cmd_get_upgrade_road_map))
if [ ! $? -eq 0 ]; then
    echo "Error on get upgrade version road map."
    exit 1
fi
echo "Mongo upgrade road map: ${versions[*]}"

current_version="3.2"
base_16_mongo=("3.6" "4.0")
base_18_mongo=("4.2" "4.4" "5.0")
for target_version in "${versions[@]}"; do
    echo "Start mongo upgrade round for target_version $target_version"

    echo "Check mongo cluster status before upgrade ..."
    if ! python $cur/mongoup.py loop_check_for $target_version; then
        echo "Error on check mongo status before upgrade target_version $target_version"
        exit 1
    fi
    if $target_version == "3.4"; then
        echo "start upgrade mongodb 3.2 to 3.4"
        ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i $cur/plan_inventory $cur/upgrade_old_version.yaml \
        --extra-vars "target_version=$target_version src_path=$cur"
        if [ ! $? -eq 0 ]; then
            echo "Error on upgrade cluster mongo target_version to $target_version."
            exit 1
        fi
        continue
    fi

#    echo "Step-Down any older version mongo Primary ..."
#    if ! python $cur/mongoup.py step_down_old_version_primary $target_version; then
#        echo "Error on step_down_old_version_primary before upgrade target_version $target_version"
#        exit 1
#    fi

#    echo "Wait mongo cluster status before upgrade ..."
#    if ! python $cur/mongoup.py loop_check_for $target_version; then
#        echo "Error on check mongo status before upgrade target_version $target_version"
#        exit 1
#    fi

    echo "Generating mongo upgrade plan_inventory ..."
    if ! python $cur/mongoup.py gen_plan_inventory $target_version; then
        echo "Error on gen_plan_inventory for target_version $target_version"
        exit 1
    fi

    cat $cur/plan_inventory

    if [[ $target_version != "3.4" ]]; then
        echo "start upgrade mongodb $current_version to $target_version"
        ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i $cur/plan_inventory $cur/upgrade_one_version.yaml \
        --extra-vars "target_version=$target_version src_path=$cur current_version=$current_version"
        if [ ! $? -eq 0 ]; then
            echo "Error on upgrade cluster mongo target_version to $target_version."
            exit 1
        fi
        continue
    fi

    $current_version=$target_version
done

echo "Clean upgrade files after upgrade success ..."
ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i $cur/mongo_cluster_inventory $cur/post_upgrade.yaml \
    --extra-vars "src_path=$cur"
if [ ! $? -eq 0 ]; then
    echo "Error on clean upgrade files after upgrade success."
    exit 1
fi

if [[ -e /usr/lib/systemd/system/elf-vm-monitor.service ]]; then
    echo "Restart elf-vm-monitor.service after upgrade success"
    if ! cluster-upgrade restart_elf_vm_monitor; then
        echo "Error on starting elf-vm-monitor.service after upgrade mongod."
        exit 1
    fi
fi

echo "Upgrade MongoDB Cluster Success."
