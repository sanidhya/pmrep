#!/bin/bash

SERVER="bumblebee"
SPATH="~/pmrep/src/server_rd"
CPATH="../src/client_wr_rd"
JOBS=100000
cores=( 1 2 4 6 )
flushes=( 1 2 4 8 16 32 64 128 )
flatency=( 0 200 400 1000 2000 4000 )
clatency=( 0 200 400 1000 2000 4000 8000 16000 )
# starting core id of the NUMA domain on which the RNIC transfers data
SCOREID=6


for flush in ${flushes[@]}
do
    for cl in ${clatency[@]}
    do
        for fl in ${flatency[@]}
        do
            for core in ${cores[@]}
            do
                for size in `cat writesize`
                do
                    # run the server
                    ssh ${SERVER} "${SPATH} -t ${SCOREID}&" &
                    sleep 2
                    echo "write-batching: ${flush} clatency: ${cl} flatency: ${fl} cores: ${core} size: ${size}"
                    v=`./${CPATH} -b ${size} -n ${core} -f ${fl} -o ${cl} -w ${flush} -j ${JOBS} | awk '{print $6}'`
                    echo -e "${size}\t${v}" >> output.core.${core}.flatency.${fl}.clatency.${cl}.batch.${flush}
                    ssh ${SERVER} "pkill server_"
                    sleep 2
                done
            done
        done
    done
done
