#!/bin/bash

set -o errexit
help() {
    echo "Usage:"
    echo "test.sh [-j ...] [-m ...]"
    echo "Description:"
    echo "-n,numanode"
    echo "-h,print this help"
    echo "-a,algo"
    echo "-q,queue num"
    echo "-d,duration"
    echo "-t,thread num"
    echo "-k,linklist num"
    echo "-l,test length"
    ./perf --list
    exit -1
}
file=./perf
if [ ! -f "$file" ]; then
    echo "$file does not exist!"
    echo "You must compile $file first!"
    exit;
fi

echo "This script is used to test all algorithms,"
echo "If you only want to test one algorithm,please use ./perf directly"
echo " "
#default params
queue_depth=256
duration=1
thread=1
queue=1
linklist=1
numa=0
length=0
hash_alg=(sha1 sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512 sm3)
cipher_alg=(aes128 aes192 aes256 sm4)
cipher_mode=(ecb cbc cfb ofb ctr ccm gcm xts ocb)

print_default(){
	echo "The following are the parameters used in this test,"
	echo "These values can be changed by entering parameters or modifying scripts"
	echo "queue num:${queue}"
	echo "duration:${duration}"
	echo "thread:${thread}"
	echo "linklist:${linklist},1 is not use linklist"
	echo "numa_node:${numa}"

}
run_all(){
echo "----run all hash tests----"
for ((i=0;i<${#hash_alg[@]};i++))
do
		echo "-------- ${hash_alg[i]}   ------"
		#./${hash_alg[i]}test -n ${number[j]} -z ${size[k]}
		./perf --algo ${hash_alg[i]} --duration ${duration} --queue ${queue} --linklist ${linklist} --numa ${numa} --thread ${thread} --depth ${queue_depth} --length ${length}
		./perf --algo hmac\(${hash_alg[i]}\) --duration ${duration} --queue ${queue} --linklist ${linklist} --numa ${numa} --thread ${thread} --depth ${queue_depth}
done
echo "---- hash test fin!---"

echo "----run cipher tests ----"
for ((i=0;i<${#cipher_alg[@]};i++))
	do
					for((l=0;l<${#cipher_mode[@]};l++))
					do
							echo "-------- ${cipher_alg[i]}-${cipher_mode[l]}-encrypt------"
							#./${cipher_alg[i]}test -n ${number[j]} -z ${size[k]} -m ${l}
							./perf --algo ${cipher_alg[i]} --mode ${cipher_mode[l]} --op enc  --duration ${duration} --queue ${queue} --linklist ${linklist} --numa ${numa} --thread ${thread} --depth ${queue_depth}
							echo "------ ${cipher_alg[i]}-${cipher_mode[l]}-decrypt------"
							./perf --algo ${cipher_alg[i]} --mode ${cipher_mode[l]} --op dec  --duration ${duration} --queue ${queue} --linklist ${linklist} --numa ${numa} --thread ${thread} --depth ${queue_depth}
					done
	done
echo "---- cipher test fin!----"
}

while getopts 'n:hq:d:t:l:k:a:' OPT; do
    case $OPT in
        n) numa="$OPTARG";;
        h) help;;
        q) queue="$OPTARG";;
	d) duration="$OPTARG";;
        t) thread="$OPTARG";;
	k) linklist="$OPTARG";;
	l) length="$OPTARG";;
	a) algo=$OPTARG;;
        ?) help;;
    esac
done

#if [ ${thread} -gt ${queue} ];then
#	queue=${thread}
#fi
print_default;
echo " "
if [ -n "${algo}" ];then
	echo "run algo ${algo}"
	./perf --algo ${algo}  --duration ${duration} --queue ${queue} --linklist ${linklist} --numa ${numa} --thread ${thread} --depth ${queue_depth} --length ${length}
else
	run_all;
fi
