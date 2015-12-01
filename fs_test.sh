#!/bin/bash

#set -e

if [ -z $1 ]; then
	echo "specify mount dir"
	exit
fi

function fail
{
	echo "Test Failed"
	echo ""
	rm -rf $test_dir
	#exit -1
}
function check_success
{
	if [ ! "$?" = "0" ]; then
		fail
	fi
}

test_dir=$1/test_dir
mkdir -p $test_dir

echo "Running tests in $test_dir"

echo "Touch"
touch $test_dir/touch_test

if [ ! -e $test_dir/touch_test ]; then
	fail
fi

#rm $test_dir/touch_test

echo "mkdir"
mkdir $test_dir/testd
check_success
rm -rf $test_dir/testd

echo "move from inside"
touch $test_dir/touch_test
check_success
pushd $test_dir >/dev/null
mv touch_test touch_moved
popd >/dev/null


echo "move from outside"
touch $test_dir/touch_test
mv $test_dir/touch_test $test_dir/touch_moved
check_success
rm $test_dir/touch_moved

echo "write"
echo "success" > $test_dir/write_test
check_success

echo "read"
cat $test_dir/write_test > /dev/null
check_success

echo "read offset"
yes | head -n 1000 > $test_dir/big
dd if=$test_dir/big of=$test_dir/big_offset seek=1000 1>/dev/null 2>1
check_success




echo "Tests passed"