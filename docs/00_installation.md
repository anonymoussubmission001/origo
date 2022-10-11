## _ORIGO_ Installation

### How to build _ORIGO_ from source
We provide an installation script to set up _ORIGO_ on an machine running Ubuntu 20.04. Please use the root user and start all commands in the `~/`, equally `/root/` folder. If you like to perform all installation steps manually, please take a look into our `installation.sh` script and pick commands as you wish. Next, we describe how you can clone the _ORIGO_ repository and perform a complete installation (including supported dependencies) using our installation script. The following steps install _ORIGO_:

#### Repository cloning and installation
1. Clone the _ORIGO_ repository to your computer using `git` (install git with the command `apt update && apt install -y git`) and the following command `cd && git clone https://github.com/anonymoussubmission001/origo.git`
2. Jump into the repository with the command `cd origo`.
3. Execute the installation script with the command `./installation.sh`
4. Run _ORIGO_ via the command line and check all available commands with `./origo`.

### How to build _ORIGO_ inside a container
Clone the _ORIGO_ repository and make sure you have a recent version of Docker installed. Next, create the docker image by running the following command from the *root* location of the _ORIGO_ repository:
```
docker build -t origo_image -f docker/Dockerfile .
```
Next, you can check your images with the command `docker images`, which should show you your image of origo called `origo_image`. With the image available, start and attach your terminal to the container as follows:
```
docker run --name origo_container -p 8080:8080 -it origo_image
```
From another terminal, you can see all running containers with the command `docker ps -a`, and you can connect to the you container with another terminal by running `docker exec -it origo_container /bin/bash`.

Inside the container, just run the origo binary by calling `./origo` to see all available commands. The installation and setup of _ORIGO_ is complete and from here, you can follow our tutorials described [here](./tutorials/).


### Private repository cloning prerequisites (not needed anymore)
0. (optional) Install git using the command `apt update && apt install -y git`. Set you private key to the environment variable with the command `export SSH_PRIVATE_KEY="your-key"` (*hint* make sure to write the command until the first \", then copy paste in your multi-line key, then add the final \") and likewise do the same with your public key `export SSH_PUBLIC_KEY="your-key.pub"`. You can inspect your keys with by printing them in the terminal with `cat ~/.ssh/id_rsa` and `cat ~/.ssh/id_rsa.pub` if you have valid keys on your computer. If you have not installed any ssh keys, please use the command `ssh-keygen -t ed25519 -C "your_email@example.com"` to generate your keys and just press enter to stick to the defaults for now. Your keys must be added to the git repo such that cloning with these keys works. Now, run the following sequence of commands to add your keys to your new machine where you want to run _ORIGO_. Please pay attention to name your existing keys (e.g. `id_rsa`, `id_rsa.pub` or `id_ed25519`, `id_ed25519.pub` as you have them and change the key names of the below code sequences where `id_cipher`, `id_cipher.pub` occurs).
```
mkdir /root/.ssh/
echo "${SSH_PRIVATE_KEY}" > /root/.ssh/id_cipher
echo "${SSH_PUBLIC_KEY}" > /root/.ssh/id_cipher.pub
touch /root/.ssh/known_hosts
ssh-keyscan gitlab.lrz.de >> ~/.ssh/known_hosts
ssh-keyscan github.com >> ~/.ssh/known_hosts
chmod 600 /root/.ssh/id_cipher
chmod 600 /root/.ssh/id_cipher.pub
```

