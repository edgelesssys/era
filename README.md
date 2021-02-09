# Edgeless Remote Attestation (era)

era performs Intel SGX DCAP verification for [Edgeless Products](https://www.edgeless.systems/products).


## Requirements

Install the [Azure DCAP Client](https://github.com/microsoft/Azure-DCAP-Client).

```bash
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
sudo apt update
sudo apt -y install az-dcap-client
```

## Install
You can use our pre-built binaries to install era on your machine.
### For the current user
```bash
wget -P ~/.local/bin https://github.com/edgelesssys/era/releases/latest/download/era
chmod +x ~/.local/bin/era
```
### Global install (requires root)
```bash
sudo -O /usr/local/bin/era https://github.com/edgelesssys/era/releases/latest/download/era
sudo chmod +x /usr/local/bin/era
```

*Note: On machines running Ubuntu, ~/.local/bin is only added to PATH when the directory exists when initializing your bash environment during login. You might need to re-login after creating the directory. Also, non-default shells such as `zsh` do not add this path by default. Therefore, if you receive `command not found: era` as an error message for a local user installation, either make sure ~/.local/bin was added to your PATH successfully or simply use the global installation method.*


## Build
To build era, [Edgeless RT](https://github.com/edgelesssys/edgelessrt) needs to be installed on your machine.
   
```bash
go build github.com/edgelesssys/era/cmd/era
```

## Usage

```bash
era -c config.json -h <IP:PORT> [-output-chain chain.pem] [-output-root root.pem] [-output-intermediate intermediate.pem]
```

For testing without quote verification use:

```bash
era -skip-quote -c config.json -h <IP:PORT> [-output-chain chain.pem] [-output-root root.pem] [-output-intermediate intermediate.pem]
```
