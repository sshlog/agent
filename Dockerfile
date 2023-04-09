FROM sshlog/build:latest AS builder

WORKDIR /build/

COPY . ./

RUN package/build_scripts/prep_repo.sh && \
    cd drone_src && \
    debuild -b -uc -us


# Deployable image
FROM ubuntu:20.04  

COPY --from=builder /build/*.deb ./

RUN apt-get update && apt-get install -y \
    libelf1 && \
    dpkg -i ./*.deb && \
    rm -rf /var/lib/apt/lists/*