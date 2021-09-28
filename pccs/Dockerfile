FROM ubuntu:20.04 AS builder

# DCAP version (github repo branch, tag or commit hash)
ARG DCAP_VERSION=DCAP_1.10.3

# update and install packages
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update -yq && \
    apt-get upgrade -yq && \
    apt-get install -yq --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    zip

# install node.js
RUN curl -sL https://deb.nodesource.com/setup_14.x | bash -
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq --no-install-recommends nodejs

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# clone DCAP repo
RUN git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git -b ${DCAP_VERSION} --depth 1

# remove conversion to hex
RUN sed -i "s/result[['pckcrl']*] = Buffer.from(result[['pckcrl']*], 'utf8').toString('hex');/\/\/ EDIT: Removed line/" SGXDataCenterAttestationPrimitives/QuoteGeneration/pccs/services/pckcrlService.js
RUN sed -i "s/crl = Buffer.from(crl, 'utf8').toString('hex');/\/\/ EDIT: Removed line/" SGXDataCenterAttestationPrimitives/QuoteGeneration/pccs/services/rootcacrlService.js

# set PWD to PCKCertSelection dir
WORKDIR /SGXDataCenterAttestationPrimitives/tools/PCKCertSelection/

# build libPCKCertSelection library and copy to lib folder
RUN make && \
    mkdir -p ../../QuoteGeneration/pccs/lib && \
    cp ./out/libPCKCertSelection.so ../../QuoteGeneration/pccs/lib/ && \
    make clean

# set PWD to PCCS dir
WORKDIR /SGXDataCenterAttestationPrimitives/QuoteGeneration/pccs/

# create cerificate
RUN mkdir -p ./ssl_key && cd ssl_key && openssl genrsa -out private.pem 2048 && openssl req -new -key private.pem -out csr.pem -subj '/C=ES/ST=NRW/L=Bochum/O=ES/CN=es.com' && openssl x509 -req -days 365 -in csr.pem -signkey private.pem -out file.crt && rm -rf csr.pem && chmod 644 ./*

# build pccs
RUN npm config set proxy $http_proxy && \
    npm config set http-proxy $http_proxy && \
    npm config set https-proxy $https_proxy && \
    npm config set engine-strict true && \
    npm ci

# build final image
FROM ubuntu:20.04

ARG USER=pccs
ARG UID=65333

# create user and a group
RUN useradd -M -U ${USER} --uid=${UID} -s /bin/false

COPY --from=builder /usr/bin/node /usr/bin/node
COPY --from=builder --chown=${USER}:${USER} /SGXDataCenterAttestationPrimitives/QuoteGeneration/pccs/ /opt/intel/pccs/

WORKDIR /opt/intel/pccs/
USER ${USER}

# copy script to setup keys
COPY setup.sh /opt/intel/pccs/setup.sh

# entrypoint to start pccs
ENTRYPOINT ["sh", "/opt/intel/pccs/setup.sh"]
