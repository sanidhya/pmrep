#!/bin/bash

SERVER="bumblebee"
SPATH="~/pmrep/src/server_sd"
CPATH="../src/client_wr_sd"
JOBS=100000
cores=( 1 2 4 6 )
flushes=( 1 2 4 8 16 32 64 128 )
flatency=( 0 200 400 1000 2000 4000 )
clatency=( 0 200 400 1000 2000 4000 8000 16000 )
maxcores=( 0 1 )
pts=( 0 2 6 7 )
pts=( 0 )
# starting core id of the NUMA domain on which the RNIC transfers data
SCOREID=6

for mc in ${maxcores[@]}
do
    for pt in ${pts[@]}
    do
        for fl in ${flatency[@]}
        do
            for core in ${cores[@]}
            do
                for size in `cat writesize`
                do
                    # run the server
                    ssh ${SERVER} "${SPATH} -t ${SCOREID} -x ${mc} &" &
                    sleep 2
                    echo "sd: max-cores: ${mc} pt: ${pt} write-batching: ${flush} clatency: ${cl} flatency: ${fl} cores: ${core} size: ${size}"
                    v=`./${CPATH} -b ${size} -n ${core} -w ${flush} -j ${JOBS} -e ${pt} | awk '{print $6}'`
                    echo -e "${size}\t${v}" >> output.sd.maxcores.${mc}.pt.${pt}.core.${core}.batch.${flush}
                    ssh ${SERVER} "pkill server_"
                    sleep 2
                done
            done
        done
    done
done
