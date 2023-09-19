
project="./test-projects/compound-protocol"
# ls $project 

if [ -d $project ]
then
    echo "${project} exists"
fi 

contracts=""

function scanContracts {
for contract in $(ls ${1})
do
    if [ -d "${1}/${contract}" ];
    then
        # echo "${1}/${contract} is dir"
        scanContracts ${1}/$contract
    else 
        if [ -f ${1}/$contract ];
        then 
            echo "${1}/$contract..."
            mkdir -p $project/result 
            python3 -m falcon.__main__ ${1}/$contract --json - > $project/result/$contract.json
            contracts="${contracts} ${1}/${contract}" 
        else
            echo "${contract} is not valid";
            # exit 1
        fi 
    fi 
done 
}
scanContracts $project/contracts
# echo $contracts
echo "done!"