import subprocess


def execute(label, command, validator, ignore_warning=False, ignore_err=False):
    print(f'[RUNNING] {label} ... ', end='', flush=True)
    result = subprocess.run(command,
                            text=True,
                            shell=True,
                            executable='/bin/bash',
                            capture_output=True)
    # encoding='cp437')

    if result.returncode != 0 or ((result.stderr != '' and not ignore_err) and not ignore_warning):
        print(f'\r[FAILED] {label}     ')
        print(f'Command \'{command}\' return code {result.returncode} '
              f'with {"not " if result.stderr != "" else ""}empty stderr.')
        print(result.stderr)
        exit(1)
    elif not validator(result.stdout):
        print(f'\r[FAILED] {label}     ')
        print(f'Command \'{command}\' failed validation with output :\n{result.stdout}')
        exit(1)
    else:
        print(f'\r[SUCCESS] {label}     ')


# Building tests
def validate_building_tests(output):
    return output == ''


# Execute tests
def validate_execution(output):
    return (output.count("[+] Peer 'yfT0rumI7AMIoueACa_EALt6aRhXLZXCqELARVWRviU' connected.") == 2
            and output.count("[-] Peer 'yfT0rumI7AMIoueACa_EALt6aRhXLZXCqELARVWRviU' disconnected.") == 2
            and output.count("[yfT0rumI7AMIoueACa_EALt6aRhXLZXCqELARVWRviU] Says : Hello world!") == 4
            and output.count("Receive reply (20b) : I got your message.") == 3
            and output.count("Server stop listening.") == 1)


# Valgrind tests
def validate_valgrind(output):
    return True


execute('Building tests', 'make -s build-test', validate_building_tests, True)
execute('Execute tests', './build/test', validate_execution)
execute('Valgrind Tests', 'valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --exit-on-first-error=yes --error-exitcode=1 build/test', validate_valgrind, ignore_err=True)
