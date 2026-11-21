#!/bin/sh
# Refuse, with a message, a runner the audit step cannot be safe on. Its
# safety rests on /bin/sh being dash: bash, even as sh, imports functions
# from BASH_FUNC_* variables, and a function can shadow a builtin the audit
# step uses while it holds the credentials. This step holds none, so it may
# use echo. action/step.sh repeats the check, silently.
# Tests use case, a reserved word, not [, a regular builtin a bash function
# could shadow; a shadowed echo loses only the message.
shell=${BASH_VERSION+bash}${ZSH_VERSION+zsh}${KSH_VERSION+ksh}
case $shell in
  ?*)
    echo "::error::The Airlock action needs /bin/sh to be dash (Debian or Ubuntu); here it is $shell."
    exit 1
    ;;
esac
case ${AIRLOCK_RUNNER_OS-} in
  Linux) ;;
  *)
    echo "::error::The Airlock action runs on Linux runners only, not ${AIRLOCK_RUNNER_OS-an unnamed one}."
    exit 1
    ;;
esac
