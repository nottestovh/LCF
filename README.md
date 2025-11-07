# LCF - Local CTF Farm

LCF — a local flag farm designed for checking and submitting flags in the attack‑defense format.
The farm focuses on local usage, making it convenient for individual participants or small teams.


## Installation

1. Clone the repository:
  git clone https://github.com/nottestovh/LCF.git
  cd LCF
2. Build the project:
   make all
   
This will compile the server and client binaries into the `bin/` directory.


## Configuration

Edit the `server/config.h` file to customize settings:
- `FLAGTTL`: Flag lifetime (time to live) in seconds.
- `SQSIZE`: Size of the flag submission queue.
- `RHOST`: IP address of the remote host where flags should be sent for checking.
- `RPORT`: Remote port of the server for flag submission.

Make sure to rebuild the project after changes:
  make all


## Usage

1. Run the server:
   bin/server
   
The server handles flag management and submissions asynchronously.

2. Run the exploit:
  bin/client ./exp

The exploit (`./exp`) should output flags to stdout.


## Cleaning Up

To clean the build artifacts:
  make clean
