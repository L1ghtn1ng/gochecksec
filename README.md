# gochecksec
A Go program that checks the security flags for Linux binaries

# Summary
This was inspired by pwntools checksec and not wanting to have to install a venv in python to be able 
to use it when you want to use do a quick check of a binaries security flags

# Building
This requires go 1.20 to build then you can use ```make -f MakeFile build``` to build the binaries.

# Installing
You can get the ```deb, rpm or archlinux pkg``` package from [here](https://github.com/L1ghtn1ng/gochecksec/releases/latest) as well as a precompiled binary for you respective CPU architecture from the ```.tar.gz``` and then move the gochecksec binary to ```/usr/local/bin/``` and you now have it installed
