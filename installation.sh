
# install golang
apt-get update && apt-get install -y wget
# wget -P /tmp https://dl.google.com/go/go1.18.5.linux-amd64.tar.gz
wget -P /tmp https://go.dev/dl/go1.19.1.linux-amd64.tar.gz
tar -C /usr/local -xzf /tmp/go1.19.1.linux-amd64.tar.gz
rm /tmp/go1.19.1.linux-amd64.tar.gz

export GOPATH=/go
export PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
mkdir -p "$GOPATH/src" "$GOPATH/bin" 
chmod -R 777 "$GOPATH"

# install dependencies
apt-get update && apt-get install -y build-essential cmake git libssl-dev sudo wget python3 vim libgmp3-dev libprocps-dev openjdk-17-jdk junit4 python3-markdown libboost-program-options-dev pkg-config

# (this part will be removed once origo is public) setup ssh configs (only required for inintal private version of origo
# mkdir /root/.ssh/
# echo "${SSH_PRIVATE_KEY}" > /root/.ssh/id_cipher
# echo "${SSH_PUBLIC_KEY}" > /root/.ssh/id_cipher.pub
# touch /root/.ssh/known_hosts
# ssh-keyscan gitlab.lrz.de >> ~/.ssh/known_hosts
# ssh-keyscan github.com >> ~/.ssh/known_hosts
# chmod 600 /root/.ssh/id_cipher
# chmod 600 /root/.ssh/id_cipher.pub

# switch to root home folder and clone repository
# cd
# git clone git@github.com:anonymoussubmission001/origo.git
cd ~/origo
# git submodule update --init --recursive

# download jar binary and compile jsnark-demo repository
cd ~/origo/dependencies/jsnark-demo/JsnarkCircuitBuilder && wget https://www.bouncycastle.org/download/bcprov-jdk15on-159.jar
mkdir -p bin
javac -d bin -cp /usr/share/java/junit4.jar:bcprov-jdk15on-159.jar $(find ./src/* | grep ".java$")

# build check if 
cd ~/origo/dependencies/libsnark-demo
export LIBSNARK_BUILD_DIR="build"
if [ -d "$LIBSNARK_BUILD_DIR" ]; then
	rm -rf $LIBSNARK_BUILD_DIR
fi

# building libsnark
mkdir build && cd build && cmake .. -DMULTICORE=ON && make
# cd ~/proxy_oracle/
# mkdir -p ./zksnark-build/jsnark/ ./zksnark-build/jsnark_interface/
cp -r ~/origo/dependencies/libsnark-demo/build/libsnark/jsnark_interface ~/origo/prover/zksnark_build/jsnark_interface/bin
# cp -r ./jsnark-demo/JsnarkCircuitBuilder/bin ./zksnark-build/jsnark/bin
# cp ./jsnark-demo/JsnarkCircuitBuilder/config.properties ./zksnark-build/jsnark/

# buil go files inside module
cd ~/origo/server
go mod tidy
go build server.go
cd ~/origo/proxy/service
go mod tidy
go build proxy.go
cd ~/origo/proxy/gitcoin_server
go mod tidy
go build main.go
cd ~/origo
go mod tidy
go build -buildvcs=false .

# output possible commands
./origo

