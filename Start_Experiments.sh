#!/bin/bash

# Define paths
INVENTORY_FILE="ansible/inventory/hosts.ini"
CLEANUP_PLAYBOOK="ansible/playbooks/clean_up.yml"
DEPLOY_PLAYBOOK="ansible/playbooks/deploy.yml"
START_NODES_PLAYBOOK="ansible/playbooks/start_nodes.yml"
REMOTE_LOG_DIR="/tmp/acting_logs"
RESULTS_FILE="experiment_results.csv"

# Initialize results file
echo "Faulty_Percentage,Dissemination_Nodes_with_20_Chunks" > $RESULTS_FILE

# Loop through faulty percentages from 0% to 100% in increments of 10%
for ((faulty_percentage=0; faulty_percentage<=100; faulty_percentage+=10)); do
    echo "Running experiment with $faulty_percentage% faulty nodes..."
    
    # Modify the Ansible playbook to update the faulty percentage (macOS compatible)
    sed -i '' "s/^ *faulty_percentage: .*/    faulty_percentage: $faulty_percentage/" $START_NODES_PLAYBOOK

    # Verify the change was made
    grep "faulty_percentage:" $START_NODES_PLAYBOOK

    # Clean up environment
    ansible-playbook -i $INVENTORY_FILE $CLEANUP_PLAYBOOK
    
    # Deploy application
    ansible-playbook -i $INVENTORY_FILE $DEPLOY_PLAYBOOK
    
    # Start nodes with updated faulty percentage
    ansible-playbook -i $INVENTORY_FILE $START_NODES_PLAYBOOK
    
    # Wait for the process to complete (20 minutes)
    echo "Waiting for 20 minutes for dissemination..."
    sleep 1200  # 1200 seconds = 20 minutes

    # Process logs remotely on each NUC
    echo "Processing logs on NUCs..."
    ansible all -i $INVENTORY_FILE -m shell -a "
        count=\$(grep -l 'owns 20' $REMOTE_LOG_DIR/dissemination_*.log | awk -F'/' '{print \$NF}' | cut -d'_' -f2 | sort -u | wc -l);
        echo \"\$(hostname),\$count\" >> /tmp/experiment_results.csv;
        echo \$count
    " | tee /tmp/experiment_summary.txt

    # Retrieve only the summary results from each NUC
    ansible all -i $INVENTORY_FILE -m fetch -a "src=/tmp/experiment_results.csv dest=/tmp/ local_tmp=/tmp/ flat=yes"

    # Aggregate results locally
    total_count=$(awk -F',' '{sum += $2} END {print sum}' /tmp/experiment_results.csv)

    echo "Faulty Percentage: $faulty_percentage%, Dissemination Nodes with 20 Chunks: $total_count"
    echo "$faulty_percentage,$total_count" >> $RESULTS_FILE

done

echo "Experiments completed! Results saved in $RESULTS_FILE"

