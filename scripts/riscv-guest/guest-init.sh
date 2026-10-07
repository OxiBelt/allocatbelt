#!/bin/sh
# PID 1 in an ephemeral, offline correctness guest. All children are fresh execs.
set -eu
scenario=bootstrap
identity=bootstrap
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
exec </dev/console >/dev/console 2>&1
. /guest/identity
fail() {
  echo "ALLOCATBELT_GUEST FAIL $scenario $identity"
  poweroff -f
  while :; do sleep 1; done
}
trap fail EXIT
case "$(uname -r)" in 7.0|7.0.*) ;; *) fail ;; esac
case " $(cat /proc/cmdline) " in
  *" allocatbelt_scenario=v-off "*) scenario=v-off ;;
  *" allocatbelt_scenario=v-on "*) scenario=v-on ;;
  *) scenario=invalid; fail ;;
esac
run() {
  label=$1
  shift
  echo "ALLOCATBELT_GUEST BEGIN $scenario $identity $label"
  "$@" >/tmp/test-output 2>&1 || { cat /tmp/test-output; fail; }
  cat /tmp/test-output
  # Required child processes also emit summaries before the parent does.
  summaries=1
  if [ "$label" = rvv-kernel ]; then summaries=2; fi
  if [ "$label" = thread-policy ]; then summaries=3; fi
  count=$(grep -Ec '^[[:space:]]*test result:' /tmp/test-output || :)
  test "$count" -eq "$summaries" || fail
  # Check every result line, including malformed, zero-test and ignored ones.
  count=$(grep -Ec '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;( finished in [0-9]+(\.[0-9]+)?s)?$' /tmp/test-output || :)
  test "$count" -eq "$summaries" || fail
  echo "ALLOCATBELT_GUEST PASS $scenario $identity $label"
}
export ALLOCATBELT_EXPECT_KERNEL=Baseline
run platform /guest/platform --test-threads=2
run region /guest/allocator-lib region:: --test-threads=2
run runtime /guest/runtime-lib runtime:: --test-threads=2
if [ "$scenario" = v-off ]; then
  run dispatch-off /guest/experimental_isa --test-threads=1
else
  test -f /proc/sys/abi/riscv_v_default_allow || fail
  echo 1 >/proc/sys/abi/riscv_v_default_allow
  export ALLOCATBELT_EXPECT_KERNEL=Rvv
  export ALLOCATBELT_REQUIRE_VECTOR_CONTROL=1
  run rvv-kernel /guest/allocator-lib arch::rvv:: --test-threads=1
  run dispatch-on /guest/experimental_isa --test-threads=1
  echo 0 >/proc/sys/abi/riscv_v_default_allow
  export ALLOCATBELT_EXPECT_KERNEL=Baseline
  run dispatch-disabled /guest/experimental_isa --test-threads=1
  run thread-policy /guest/riscv_vector_control --test-threads=1
fi
echo "ALLOCATBELT_GUEST COMPLETE $scenario $identity"
trap - EXIT
poweroff -f
while :; do sleep 1; done
