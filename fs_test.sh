#!/bin/bash

#set -e

if [ -z $1 ]; then
	echo "specify mount dir"
	exit
fi

function fail
{
	echo "Test Failed"	
	
	#exit -1
}
function check_success
{
	if [ ! "$?" = "0" ]; then
		fail
	else
		echo "."
	fi
	echo ""
}
function make_small
{
	yes | head -n 1000 > $test_dir/small
}

test_dir=$1/test_dir
rm -rf $test_dir
mkdir -p $test_dir

echo "Running tests in $test_dir"

echo "Touch"
touch $test_dir/touch_test
check_success
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

echo "write"
echo "success" > $test_dir/write_test
check_success

echo "write offset"
dd if=/dev/zero of=$test_dir/offset_test seek=7 count=100 bs=100 1>/dev/null 2>&1
check_success

echo "read"
cat $test_dir/write_test > /dev/null
check_success

echo "read offset"
make_small
dd if=$test_dir/small of=$test_dir/big_offset seek=100 bs=100 1>/dev/null 2>&1
check_success

echo "symlink"
pushd $test_dir >/dev/null
echo "the link" > link_src
ln -s link_src link_dest
check_success
popd >/dev/null

echo "truncate"
make_small
truncate -s 0 $test_dir/small
check_success




echo "Tests passed"