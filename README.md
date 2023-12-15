# Building and Installing Enoki Kernel

## Prerequisites
Setting up Enoki Kernel requires a Linux distribution that uses Linux kernel version
5.11. This is because some aspects of building the kernel depend on the headers from
5.11.

Check which kernel version is installed by going to a terminal in your Linux distribution 
and running `uname -r`. If the output of this command starts with something like `5.11`, you should be able to start from **Part 1** of this guide. **If you see some other version, please start from Part 0**, which will walkthrough the kernel version modification process on Ubuntu 20.04. 

## Part 0: Changing kernel version to 5.11

For this setup, we will be using Ubuntu 20.04. Although Ubuntu 20.04 comes installed with Linux kernel version 5.15 (as of September 2023), it is possible to downgrade the kernel to 5.11 with a few simple steps.

From a clean install of Ubuntu 20.04 (from a VM or otherwise), run in the terminal:
```
apt-cache search linux-image*-5.11.0 | grep "generic"
```
Several options should show up. Pick any of the Linux kernel images that appear and 
install them using 
```
sudo apt install linux-image-5.11.0-XX-generic
sudo apt install linux-headers-5.11.0-XX-generic
```
where the **XX** is the revision number that you have chosen.

If your OS is not configured to launch GRUB on startup, enable it by editing the file `/etc/default/grub` to include `GRUB_TIMEOUT_STYLE=menu` and `GRUB_TIMEOUT=5` (replacing whatever value is already present for these options). After editing, make sure to run `sudo update-grub`.

Reboot the system with `sudo reboot`. On reboot, the GRUB menu should pop up. Navigate to "Advanced Options for Ubuntu" and select the option "Ubuntu, with Linux 5.11.0-XX-generic", where XX is the revision number previously chosen.

Your kernel version should now be 5.11.0, which you can verify by running `uname -r`

## Part 1: Installing dependencies

Once your Linux kernel is on some revision of 5.11.0, you can begin installing the dependencies needed to build Enoki kernel.

First, get the build dependencies for 5.11.0 by running:
```
sudo apt-get build-dep linux linux-image-$(uname -r)
```
If this command does not work and you are using Ubuntu, check if `/etc/apt/sources.list` has the `deb-src` lines uncommented for `xxxx main restricted` and `xxx-updates main restricted`, where **xxxx** is the Ubuntu version. If these lines are commented out, please uncomment them and then rerun the apt-get command above.

After this, install additional dependencies using the following command:
```
sudo apt-get install libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf llvm zstd
```

## Part 2: Building and Installing Enoki Kernel

Clone this repo into your desired location.

`cd` into the repo's directory. Run the command
```
make -j $(getconf _NPROCESSORS_ONLN) bindeb-pkg LOCALVERSION=-custom
```

This will start building Enoki Kernel. Go ahead and grab a cup of your favorite beverage, as it will take some time to build.

Once the build is finished, the kernel image and headers will be generated in the repo's parent directory. Navigate to the parent directory.

The build output should specify the version of the custom kernel (which we will refer to as **custom-XXX**).
To install the generated `.deb` binary packages, execute the command:
```
sudo dpkg -i linux-*5.11.0*custom-XXX*.deb
```
**If this is your first time installing Enoki Kernel, you may find it easier to just do**
```
sudo dpkg -i *.deb
```

Once `dpkg` finishes installing the binary packages, perform `sudo reboot`.

When the GRUB menu pops up, navigate to "Advanced Options for Ubuntu" and look for the option "Ubuntu, with Linux 5.11.0-custom". Select this option, which enable Ubuntu to run with Enoki Kernel.


### Notes
- There may be errors that prevent a build from successfully completing. Most of the time this is due to a missing dependency. The build output should give enough information to 
identify the missing dependency and install it with `apt` (or which ever other package manager you use). Rerun the build command from above after installing the dependency.
- When running `apt` or `dpkg`, there may be errors related to locks. Ensure that all known
updates are finished. If so, reboot your system, which should clear all held locks.
