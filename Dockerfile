# Stage 1: Build stage
FROM gramineproject/gramine:1.7-focal AS builder

RUN apt-get update && \
    apt-get install -y build-essential && \
    apt-get install -y python3.8 python3-pip python3-venv

# Install pipenv
RUN pip3 install pipenv

# Install PyInstaller
RUN pip3 install pyinstaller
   
# Set the working directory
WORKDIR /app

# Copy Pipenv files and install dependencies
COPY Pipfile ./
RUN pip install pipenv && pipenv install --dev

# Copy the rest of the application code
COPY . .

RUN rm -rf dist/

# Install pyinstaller or any other tool needed to generate a binary
RUN pipenv install pyinstaller

RUN mkdir -p /app/lib

RUN cp /lib/x86_64-linux-gnu/libdl.so.2 /app/lib/ && \
    cp /lib/x86_64-linux-gnu/libz.so.1 /app/lib/ && \
    cp /lib/x86_64-linux-gnu/libpthread.so.0 /app/lib/ && \
    cp /lib/x86_64-linux-gnu/libc.so.6 /app/lib/ && \
    cp /lib64/ld-linux-x86-64.so.2 /app/lib/

RUN ls /app/lib

RUN chmod +x /app/lib/*

# Create the binary
RUN pipenv run pyinstaller --add-binary '/app/lib/libdl.so.2:lib' \
    --add-binary '/app/lib/libz.so.1:lib' \
    --add-binary '/app/lib/libpthread.so.0:lib' \
    --add-binary '/app/lib/libc.so.6:lib' \
    --add-binary '/app/lib/ld-linux-x86-64.so.2:lib' \
    uProbe/uProbe.py

# Set up work directory

# Stage 1: Build stage
FROM gramineproject/gramine:1.7-focal

RUN apt-get update && apt-get install -y \
    make \
    gcc \
    linux-tools-5.15.0-117-generic \
    linux-cloud-tools-5.15.0-117-generic \
    linux-cloud-tools-generic \
    linux-tools-common

WORKDIR /app

# Copy all files from the host work directory to the container's work directory
COPY --from=builder /app/dist /app/dist

COPY ./manifests /app/manifests

COPY ./Makefile /app/Makefile

COPY ./app/web-server.py /app/web-server.py

COPY ./entrypoint.sh /app/.

RUN echo "10.10.5.10 agent" >> /etc/hosts
RUN ls /app/dist

# Build the application with debug information
RUN make DEBUG=1

RUN chmod +x /app/entrypoint.sh
# Set the entrypoint to /bin/sh so we can exec into the container
ENTRYPOINT ["/bin/sh"]