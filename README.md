# Edgeless Remote Attestation (era)

era is a command-line tool that obtains attested TLS certificates (X.509) from services running in Intel SGX enclaves. Currently, era only works with Intel SGX DCAP (Data Center Attestation Primitives). era uses its own [protocol](#protocol) to obtain the certificate and the corresponding attestation statement from a service. Software that supports the era protocol includes [MarbleRun](https://github.com/edgelesssys/marblerun) and [EdgelessDB](https://github.com/edgelesssys/edgelessdb) from [Edgeless Systems](https://edgeless.systems/).

era verifies the validity of the attestation statement with respect to a given policy/configuration file. On success, it writes out the service's X.509 certificate. The certificate can then be used to talk securely to the "enclaved" service.

The following is an example of a configuration file.

```json
{
	"SecurityVersion": 1,
	"ProductID": 16,
	"SignerID": "67d7b00741440d29922a15a9ead427b6faf1d610238ae9826da345cea4fee0fe"
}
```

Here, the triplet `SecurityVersion`, `ProductID`, and `SignerID` identifies the enclave configuration of the service. `SignerID` corresponds to the `MRSIGNER` field in the SGX DCAP attestation statement. It's the fingerprint of the signing key used to sign the enclave package. Here, it's the fingerprint of Edgeless Systems's signing key. `ProductID = 16` corresponds to EdgelessDB and `SecurityVersion` indicates the minimum required security patch level. So for this particular configuration file, era would make sure that the remote service is an official EdgelessDB release issued by Edgeless Systems with at least security patch level `1` and that the service is indeed running in an SGX enclave.

Alternatively to the triplet `SecurityVersion`, `ProductID`, and `SignerID`, era also supports the use of `UniqueID`, which corresponds to the `MRENCLAVE` field in an SGX DCAP attestation statement. It's essentially a cryptographic hash of a particular enclave package. Use `UniqueID` if you need to make sure that the service you're talking to is running a specific enclave package.

## Requirements

To verify the genuinity of a service's attestation statement, era requires certain "collateral" information from Intel. The information is specific to the CPU the service is running on. 

### Azure

If your service is running in Azure, it is sufficient to install the [Azure DCAP Client](https://github.com/microsoft/Azure-DCAP-Client) alongside era on the client as follows: 

```bash
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add
sudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/ubuntu/`lsb_release -rs`/prod `lsb_release -cs` main"
sudo apt install az-dcap-client
```

### On-premises

If your service is running on-prem, you need to run your own Provisioning Certificate Caching Service (PCCS) alongside it and install and configure corresponding DCAP libraries on the client. This is a general requirement of Intel SGX DCAP. Intel provides a corresponding [setup guide](https://software.intel.com/content/www/us/en/develop/articles/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html).

## Install

You can use our pre-built binaries to install era on your machine.
### For the current user
```bash
wget -P ~/.local/bin https://github.com/edgelesssys/era/releases/latest/download/era
chmod +x ~/.local/bin/era
```
### Global install (requires root)
```bash
sudo wget -O /usr/local/bin/era https://github.com/edgelesssys/era/releases/latest/download/era
sudo chmod +x /usr/local/bin/era
```

*Note*: On machines running Ubuntu, ~/.local/bin is only added to PATH when the directory exists when initializing your bash environment during login. You might need to re-login after creating the directory. Also, non-default shells such as `zsh` do not add this path by default. Therefore, if you receive `command not found: era` as an error message for a local user installation, either make sure ~/.local/bin was added to your PATH successfully or simply use the global installation method.

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

## Protocol

The era protocol is simple. In a nutshell, an era-compatible service exposes the `/quote` endpoint via HTTPS. The endpoint returns the service's X.509 certificate alongside a corresponding Intel SGX DCAP attestation statement, also known as "quote", in JSON format. The format corresponds to the following Go struct:

```go
type certQuoteResp struct {
	Cert  string
	Quote []byte
}
```
