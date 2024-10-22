#!/usr/bin/env bash

layered_bin=${1:-../../../../target/release/scx_layered}
test_progs=( "../../../../target/release/affinity_test" "stress-ng -c 2 -f 1 -t 30" "stress-ng -c 2 -f 1 -t 30" )
test_scripts=( "layer_affinity.bt" "layer_node.bt" "layer_llc.bt" )
test_configs=( "affinity.json" "numa.json" "llc.json" )

for i in "${!test_scripts[@]}"; do
	test_script="${test_scripts[$i]}"
	test_config="${test_configs[$i]}"
	test_prog="${test_progs[$i]}"

	sudo pkill -9 -f scx_layered 2>/dev/null
	sudo "${layered_bin}" --stats 1 "f:${test_config}" -v &
	layered_pid=$!

	echo "layered pid ${layered_pid}"
	sleep 2

	"${test_prog}" &
	test_pid=$!

	echo "test pid ${test_pid}"
	sleep 1

	sudo "./${test_script}" "${test_pid}"
	test_exit=$?

	pidof scx_layered && sudo pkill -9 -f scx_layered
	# always cleanup test pid
	sudo kill -9 "${test_pid}"

	if [ $test_exit -ne 0 ]; then
		echo "test script ${test_script} failed: ${test_exit}"
		exit $test_exit;
	fi
	echo "test script ${test_script} passed: ${test_exit}"
done
