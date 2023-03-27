#! /usr/bin/python3

import subprocess, requests, tarfile, shutil, os, glob, argparse

parser = argparse.ArgumentParser(description='Kernel install script for tempesta-fw')
parser.add_argument('--reboot', type=bool, default=None,
                    help='Reboot flag. Reboot at finish if present')
parser.add_argument('--make_default', type=bool, default=None,
                    help='Set kernel as default.')
parser.add_argument('--registry_creds', type=str, default=None,
                    help='Registry credentials. If provided deb packages will bu pushed')
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
    ["git log -n 1 --pretty=format:%H -- linux-5.10.35.patch"],
    stdout=subprocess.PIPE,
    shell=True,
    cwd=tempesta_path
    )
output, err = p_kern_hash.communicate()
current_patch_hash = output.decode("utf-8").strip()[:7]
current_kernel_hash = os.uname().release.strip().split('-')[-1][:7]

if current_patch_hash == current_kernel_hash:
    print('Same kernel version installed')

else:
    print('New kernel version found')
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
            with subprocess.Popen(["apt", "install", f"*5.10.35.tfw-{current_patch_hash}"],
                          stdout=subprocess.PIPE) as p:
                for line in p.stdout:
                    print(line, end='\n')

        # Else - Run local build
        else:
            print('Need to get another version of kernel')
            print(f'{current_patch_hash} != {current_kernel_hash}')
            
            

            # Step 1: Download sources
            print('Step 1: Downloading 5.10.35 sources...')
            url = 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/snapshot/linux-5.10.35.tar.gz'
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
            with open('linux-5.10.35/Makefile') as f:
                    data = f.read()
                    data = data.replace('EXTRAVERSION =', f'EXTRAVERSION = .tfw-{current_patch_hash}')
                    data = data.replace('NAME = Dare mighty things', f'NAME = Some test string')
            with open(r'linux-5.10.35/Makefile', 'w') as file:
                file.write(data)
            shutil.copyfile(f'{tempesta_path}/linux-5.10.35.patch', 'linux-5.10.35/linux-5.10.35.patch')
            with subprocess.Popen(["patch -p1 < linux-5.10.35.patch"],
                                  stdout=subprocess.PIPE,
                                  shell=True,
                                  cwd=f"linux-5.10.35") as p:
                output, err = p.communicate()
                patch_out = output.decode("utf-8").strip()

            # Step 4: config
            if os.path.exists('.config'):
                print('Step 4: Predefined .config found...')
                subprocess.Popen(['cp', '.config', 'linux-5.10.35/config'], stdout=subprocess.PIPE)
            else:
                print('Step 4: Use OS .config...')
                subprocess.Popen(['cp', f'/boot/config-{os.uname().release}', '.config'],
                             stdout=subprocess.PIPE,
                             cwd=f"linux-5.10.35")
            
            # Step 5: Build kernel
            print('Step 5: Make deb-pkg...')
            with subprocess.Popen(["make", "deb-pkg"],
                                  stdout=subprocess.PIPE,
                                  bufsize=1, universal_newlines=True,
                                  cwd=f"linux-5.10.35") as p:
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
                            "@./{file}" http://tempesta-vm.cloud.cherryservers.net:8081/repository/tempesta/')

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
                        kernel_id = [s for s in row.split() if f'linux-5.10.35.tfw-{current_patch_hash}' in s][0].strip("'")

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

    if args.reboot:
        print('Kernel installed, now need to reboot')
        subprocess.Popen(['sudo', '-S', 'reboot'], stdout=subprocess.PIPE)
