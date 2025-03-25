#!/usr/bin/env bash

# Check OS
if [ -f /etc/os-release ]; then
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s)
    VER=$(uname -r)
    echo "This Linux version is too old: $OS:$VER, we don't support!"
    exit 1
fi

sudo -v
if [ $? == 1 ]
then
    echo "Without root permission, you cannot run the test due to our test is using namespace"
    exit 1
fi

while getopts 'o' OPT;
do
    case $OPT in
        o) DUMP_NS=True;;
    esac
done
shift $(($OPTIND - 1))

TEST_POOL="All|TestPDUSessionSendData"
if [[ ! "$1" =~ $TEST_POOL ]]
then
    echo "Usage: $0 [ ${TEST_POOL//|/ | } ]"
    exit 1
fi

if [ $1 == "All" ]; then
    echo "Running All Tests"
    echo
    mkdir -p testing_output
    IFS='|' read -ra ADDR <<< "$TEST_POOL"
        for i in "${ADDR[@]}"; do
            if [ $i == "All" ]; then
                continue
            fi
            echo "$i"
            echo "    Output saved to testing_output/$i.log"
            exec $(realpath $0) $i &> testing_output/$i.log &
            wait
            STATUS=$(grep -E "\-\-\-.*:" testing_output/$i.log)
            if [ ! -z "$STATUS" ]; then
                echo "$STATUS" | while read -r a; do echo "    ${a:4}"; done
            else
                echo "    Failed"
            fi
            echo
        done
    exit 1
fi

GOPATH=$HOME/go
if [ $OS == "Ubuntu" ]; then
    GOROOT=/usr/local/go
elif [ $OS == "Fedora" ]; then
    GOROOT=/usr/lib/golang
fi
PATH=$PATH:$GOPATH/bin:$GOROOT/bin

UPFNS="UPFns"
EXEC_UPFNS="sudo -E ip netns exec ${UPFNS}"

export GIN_MODE=release

function terminate()
{
    sleep 3
    sudo killall -15 upf

    if [ ${DUMP_NS} ]
    then
        # kill all tcpdump processes in the default network namespace
        sudo killall tcpdump
        sleep 1
    fi

    sudo ip link del veth0
    sudo ip netns del ${UPFNS}
    sudo ip addr del 10.60.0.1/32 dev lo

    if [[ "$1" == "TestNon3GPP" ]]
    then
        if [ ${DUMP_NS} ]
        then
            cd .. && sudo ip xfrm state > ${PCAP_PATH}/NWu_SA_state.log
        fi
        sudo ip xfrm policy flush
        sudo ip xfrm state flush
        sudo ip netns del ${UENS}
        removeN3iwfInterfaces
        sudo ip link del veth2
        sudo killall n3iwf
        ps aux | grep test.test | awk '{print $2}' | xargs sudo kill -SIGUSR1
    fi

    if [[ "$1" == "TestMultiAmfRegistration" ]]
    then
        cd .. && ./force_kill.sh
    fi

    if [[ "$1" == "TestNasReroute" ]]
    then
        cd .. && ./force_kill.sh
    fi

    sleep 5
}

function handleSIGINT()
{
    echo -e "\033[41;37m Terminating due to SIGINT ... \033[0m"
    terminate $1
}

trap handleSIGINT SIGINT




# Setup network namespace
sudo ip netns add ${UPFNS}

sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip addr add 10.60.0.1 dev lo
sudo ip addr add 10.200.200.1/24 dev veth0  # RAN N3 & SMF PFCP
sudo ip addr add 10.200.200.2/24 dev veth0  
sudo ip addr add 10.200.200.3/24 dev veth0  # NRF

sudo ip link set veth1 netns ${UPFNS}

${EXEC_UPFNS} ip link set lo up
${EXEC_UPFNS} ip link set veth1 up
${EXEC_UPFNS} ip addr add 10.60.0.101 dev lo
${EXEC_UPFNS} ip addr add 10.200.200.101/24 dev veth1   # UPF N4 PFCP address 
${EXEC_UPFNS} ip addr add 10.200.200.102/24 dev veth1   # UPF N3 GTP-U address
${EXEC_UPFNS} ip addr add 10.200.200.103/24 dev veth1   # UPF SBI address

if [ ${DUMP_NS} ]
then
    PCAP_PATH=testpcap
    mkdir -p ${PCAP_PATH}
    ${EXEC_UPFNS} tcpdump -U -i any -w ${PCAP_PATH}/${UPFNS}.pcap &
    sudo -E tcpdump -U -i lo -w ${PCAP_PATH}/default_ns.pcap &
fi

# Start UPF
${EXEC_UPFNS} ./bin/upf -c ./config/upfcfg.test_data_plane.yaml & UPF_PID=$!

# start other NF & test
cd test
$GOROOT/bin/go test -v -vet=off -run "^$1$" -args $2

# Test UPF SBI API
printf "\n\n\n\n\n ------------- Test UPF SBI API ----------------\n"
printf "GET 10.200.200.103:8000/nwdaf-oam/packets-count: \n"
curl 10.200.200.103:8000/nwdaf-oam/packets-count
printf "\n ------------------- \n\n"

terminate $1
