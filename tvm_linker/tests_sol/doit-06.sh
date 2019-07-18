address1=9357094a867a96b9e6ccd69043ae3c34fe09e59d3826ca5f1319ae822e8bcabc
address1short=`echo $address1 | cut -c 1-8`
msginit1=$address1short-msg-init.boc
msgbody1=$address1short-msg-body.boc
address2=fb5a6f44aa1edb15989106e3444bb03a91a280b5c0ae26c5069183dfb2d2f237
address2short=`echo $address2 | cut -c 1-8`
msginit2=$address2short-msg-init.boc
msgbody2=$address2short-msg-body.boc

rm -f *.tvc *.boc *.tmp

source set_env.sh

$linker compile --lib ../stdlib_sol.tvm ./contract06-a.code --abi-json ./contract06-a.abi.json
$linker compile --lib ../stdlib_sol.tvm ./contract06-b.code --abi-json ./contract06-b.abi.json

if [ ! -f "${address1}.tvc" ]; then
  echo "FILE NOT FOUND! ${address1}.tvc"
  exit 1
fi

if [ ! -f "${address2}.tvc" ]; then
  echo "FILE NOT FOUND! ${address2}.tvc"
  exit 1
fi

$linker message $address1 --init -w 0
$linker message $address2 --init -w 0

zeroes=0000000000000000000000000000000000000000000000000000000000000000

$linker message $address1 -w 0 --abi-json contract06-a.abi.json \
	--abi-method constructor_external	\
	--abi-params "{}" \
	--setkey ../key1

$emulator/create-msg --type transfer --src $zeroes --dst $address1 --value 10000000 --out sendmoney1.boc
$emulator/create-msg --type transfer --src $zeroes --dst $address2 --value 10000000 --out sendmoney2.boc


echo "-------------------------------"
$tlc -f sendmoney1.boc
$tlc -f sendmoney2.boc
echo "-------------------------------"
sleep 5
echo "-------------------------------"
$tlc -a 0:$address1
$tlc -a 0:$address2

echo "-------------------------------"
$tlc -f $msginit1
$tlc -f $msginit2
echo "-------------------------------"
sleep 5

echo "-------------------------------"
$tlc -a 0:$address1
$tlc -a 0:$address2

echo "-------------------------------"
$tlc -f $msgbody1
sleep 5
echo "-------------------------------"
$tlc -a 0:$address1
$tlc -a 0:$address2
echo "-------------------------------"

$linker message $address1 -w 0 --abi-json contract06-a.abi.json \
	--abi-method "setAllowance_external"	\
	--abi-params "{\"anotherContract\":\"0x${address2}\", \"amount\":\"0x12345678\"}" \
	--setkey ../key1

echo "-------------------------------"
$tlc -f $msgbody1
sleep 5
echo "-------------------------------"

$linker message $address2 -w 0 --abi-json contract06-b.abi.json \
	--abi-method "getMyCredit_external"	\
	--abi-params "{\"bank\":\"0x${address1}\"}"

echo "-------------------------------"
$tlc -f $msgbody2
sleep 5
echo "-------------------------------"

sleep 5
echo "-------------------------------"
$tlc -a 0:$address1
$tlc -a 0:$address2
echo "-------------------------------"

