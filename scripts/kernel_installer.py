#! /usr/bin/python3

import subprocess, requests, tarfile, shutil, os, glob, argparse, sys

KERNEL_VERSION = '5.10.35'

parser = argparse.ArgumentParser(description='Kernel install script for tempesta-fw')
parser.add_argument('--reboot', type=bool, default=False,
                    help='Reboot flag. Reboot at finish if present')
parser.add_argument('--make_default', type=bool, default=True,
                    help='Set kernel as default.')
parser.add_argument('--registry_creds', type=str, default=None,
                    help='Registry credentials. If provided deb packages will bu pushed')
parser.add_argument('--registry', type=str, default=None,
                    help='Registry URL.')

args = parser.parse_args()

# Check root
if os.geteuid() != 0:
    print("You aren't root")
    os._exit(1)

def add_repo(file_path: str, string_to_add: str) -> None:
    # Add tempesta repo if not present
    with open(file_path, "r+") as file:
        lines = file.readlines()
        if string_to_add + "\n" not in lines:
            file.write("\n" + string_to_add)
    # Also add GPG key
    print('Add GPG key')
    os.system('apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 36E626F4BEBEB6A8')

add_repo('/etc/apt/sources.list',
                   'deb http://tempesta-vm.cloud.cherryservers.net:8081/repository/tempesta/ focal main')

script_path = os.path.dirname(os.path.realpath(__file__))
tempesta_path = os.path.dirname(script_path)

# Prereq: Check is right kernel already installed
p_kern_hash = subprocess.Popen(
    [f"git log -n 1 --pretty=format:%H -- linux-{KERNEL_VERSION}.patch"],
    stdout=subprocess.PIPE,
    shell=True,
    cwd=tempesta_path
    )
output, err = p_kern_hash.communicate()
current_patch_hash = output.decode("utf-8").strip()[:7]
current_kernel_hash = os.uname().release.strip().split('-')[-1][:7]

if current_patch_hash == current_kernel_hash:
    print('Same kernel version installed')
    sys.exit(0)
else:
    print('New kernel version is required')
    # Step 0: Check if kernel already present in repo
    with subprocess.Popen(["apt-get", "update"],
                          stdout=subprocess.PIPE) as p:
        for line in p.stdout:
            print(line, end='\n') # process line here

    with subprocess.Popen(["apt-cache", "search", f"{current_patch_hash}"],
                          stdout=subprocess.PIPE) as packages:
        # If present in repo - install from apt
        if len(packages.stdout.readlines()) >= 3:
            print('Kernel found, installing from repo')
            with subprocess.Popen(["apt", "install", f"*{KERNEL_VERSION}.tfw-{current_patch_hash}"],
                          stdout=subprocess.PIPE) as p:
                for line in p.stdout:
                    print(line, end='\n')

        # Else - Run local build
        else:
            print('Need build new kernel image')
            print(f'{current_patch_hash} != {current_kernel_hash}')
            
            

            # Step 1: Download sources
            print(f'Step 1: Downloading {KERNEL_VERSION} sources...')
            url = f'http://tempesta-vm.cloud.cherryservers.net:8081/repository/maven-releases/tempesta/linux-kernel-source/{KERNEL_VERSION}/linux-kernel-source-{KERNEL_VERSION}.tar.gz'
            r = requests.get(url, allow_redirects=True)
            open('download.tar.gz', 'wb').write(r.content)
            print('Done')

            # Step 2: Untar
            print('Step 2: Untar sources...')
            my_tar = tarfile.open('download.tar.gz')
            my_tar.extractall('.') # specify which folder to extract to
            my_tar.close()
            print('Done')

            # Step 3: Apply EXTRAVERSION and patch
            print('Step 3: Patch...')
            with open(f'linux-{KERNEL_VERSION}/Makefile') as f:
                    data = f.read()
                    data = data.replace('EXTRAVERSION =', f'EXTRAVERSION = .tfw-{current_patch_hash}')
                    data = data.replace('NAME = Dare mighty things', f'NAME = Some test string')
            with open(f'linux-{KERNEL_VERSION}/Makefile', 'w') as file:
                file.write(data)
            shutil.copyfile(f'{tempesta_path}/linux-{KERNEL_VERSION}.patch', f'linux-{KERNEL_VERSION}/linux-{KERNEL_VERSION}.patch')
            with subprocess.Popen([f"patch -p1 < linux-{KERNEL_VERSION}.patch"],
                                  stdout=subprocess.PIPE,
                                  shell=True,
                                  cwd=f"linux-{KERNEL_VERSION}") as p:
                output, err = p.communicate()
                patch_out = output.decode("utf-8").strip()

            # Step 4: config
            if os.path.exists('.config'):
                print('Step 4: Predefined .config found...')
                subprocess.Popen(['cp', '.config', f'linux-{KERNEL_VERSION}/config'], stdout=subprocess.PIPE)
            else:
                print('Step 4: Use OS .config...')
                subprocess.Popen(['cp', f'/boot/config-{os.uname().release}', '.config'],
                             stdout=subprocess.PIPE,
                             cwd=f"linux-{KERNEL_VERSION}")
            
            # Step 5: Build kernel
            print('Step 5: Make deb-pkg...')
            with subprocess.Popen(["make", "deb-pkg"],
                                  stdout=subprocess.PIPE,
                                  bufsize=1, universal_newlines=True,
                                  cwd=f"linux-{KERNEL_VERSION}") as p:
                for line in p.stdout:
                    print(line, end='') # process line here

            if p.returncode != 0:
                raise subprocess.CalledProcessError(p.returncode, p.args)

            # Push to registry
            if args.registry_creds is not None:
                print('Step 5.1: Push to registry...')
                for file in glob.glob('*.deb'):
                    os.system(f'curl -u "{args.registry_creds}" \
                            -H "Content-Type: multipart/form-data" --data-binary \
                            "@./{file}" {args.registry}')

            # Step 6: Install and reboot
            os.system('sudo dpkg -i *.deb')

    if args.make_default:
        # Step 6.1: Optional. Edit grub.cfg and patch /etc/default/grub to make new kernel default
        print('Step 6.1: Optional. Edit grub.cfg and /etc/default/grub to set new kernel as default')
        with open(r'/boot/grub/grub.cfg', 'r') as fp:
            lines = fp.readlines()
            for row in lines:
                if row.find('submenu') != -1:
                    submenu_id = [s for s in row.split() if 'gnulinux' in s][0].strip("'")
                elif row.find(f'.tfw-{current_patch_hash}') != -1 and row.find('menuentry') != -1:
                        kernel_id = [s for s in row.split() if f'linux-{KERNEL_VERSION}.tfw-{current_patch_hash}' in s][0].strip("'")

        with open('/etc/default/grub', 'r') as file:
            data = file.read()
            newdata = []
            for s in data.split('\n'):
                if s.find('GRUB_DEFAULT=') != -1:
                    s = f'GRUB_DEFAULT={submenu_id}>{kernel_id}'
                newdata.append(s+'\n')

        with open('/etc/default/grub', 'w') as file:
            for s in newdata:
                file.write(s)

        print('update-grub')
        with subprocess.Popen(['sudo', '-S', 'update-grub'], stdout=subprocess.PIPE) as updategrub:
            updategrub.wait()
            for line in updategrub.stdout:
                print(line, end='')

    print('Kernel installed, now need to reboot')
    # if args.reboot:
    #     subprocess.Popen(['sudo', '-S', 'reboot'], stdout=subprocess.PIPE)

    sys.exit(1)
