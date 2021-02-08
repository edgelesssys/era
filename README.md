# Edgeless Remote Attestation (era)

era performs Intel SGX DCAP verification for [Edgeless Products](https://www.edgeless.systems/products).


## Requirements

Install the [Azure DCAP Client](https://github.com/microsoft/Azure-DCAP-Client)

```bash
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
sudo apt update
sudo apt -y install az-dcap-client
```

## Install

1. Download prebuild binaries from our [releases](https://github.com/edgelesssys/era/releases)
2. Install from source (requires [EdgelessRT](https://github.com/edgelesssys/edgelessrt))
   
   ```bash
    go install github.com/edgelesssys/era/cmd/era
    ```

## Usage

```bash
era -c config.json -h <IP:PORT> [-output-chain chain.pem] [-output-root root.pem] [-output-intermediate intermediate.pem]
```

For testing without quote verification use:

```bash
era -skip-quote -c config.json -h <IP:PORT> [-output-chain chain.pem] [-output-root root.pem] [-output-intermediate intermediate.pem]
```
