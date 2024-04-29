#!/usr/bin/env bash

killall flask 2>/dev/null
sudo systemctl restart redis > /dev/null 2>&1

# start clean
echo FLUSHALL | redis-cli
rm -rf keys files;

echo "[+] Environment cleaned"

# generate the trust chain
python3 pki.py

echo "[+] PKI generated"

# start the server
FLASK_DEBUG=1 flask --app server run > /dev/null 2>&1 &

# give a moment to the server
sleep 3

echo "[+] Server started"

# generate journalists
for i in $(seq 0 9); do python3 journalist.py -j $i -a upload_keys; done;

echo "[+] Journalists setup complete"

# submit a bunch of things
source1=`python3 source.py -a submit -m "First demo message" | cut -d : -f 2`
source2=`python3 source.py -a submit -m "Second demo message" | cut -d : -f 2`
source3=`python3 source.py -a submit -m "Third demo message" | cut -d : -f 2`


echo "[+] Source 1: ${source1}"
echo "[+] Source 2: ${source2}"
echo "[+] Source 3: ${source3}"

# fetch from journalist 5
journalist5=`python3 journalist.py -j 5 -a fetch | tail -n 4`

echo "[+] Printing messages received by Journalist 5"

for message_id in $journalist5; do
	python3 journalist.py -j 5 -a read -i $message_id
done

echo "[+] Printing messages received by Journalist 8 and replying"

# fetch from journalist 8
journalist8=`python3 journalist.py -j 8 -a fetch | tail -n 4`

for message_id in $journalist8; do
	python3 journalist.py -j 8 -a read -i $message_id
	# reply to every message
	python3 journalist.py -j 8 -a reply -i $message_id -m "Reply to $message_id"
done

echo "[+] Fetching and printing replies to sources"

# fetch the replies using the sources' passphrases
reply1=`python3 source.py -p $source1 -a fetch | tail -n 2`
reply2=`python3 source.py -p $source2 -a fetch | tail -n 2`
reply3=`python3 source.py -p $source3 -a fetch | tail -n 2`

echo "[+] Source 1"
python3 source.py -p $source1 -a read -i $reply1
echo "[+] Source 2"
python3 source.py -p $source2 -a read -i $reply2
echo "[+] Source 3"
python3 source.py -p $source3 -a read -i $reply3

echo "[+] Demo complete"

killall flask
