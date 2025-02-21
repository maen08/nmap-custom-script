# nmap-custom-script
NMAP custom script that prioritize the detected vulnerabilities based on defined metrics


## Prerequisite
- NMAP
- docker
- Linux / Windows machine

  
## Custom metrics
- Severity
- Exploitability
- CVSS score

## How it works
- Once you run the script agains the target, first it will scan for a number of vulnerabilities (listed) and then it will give the output listed based on priority

```
# Run the script command


# Example of output results


```

## Testing
- Setup a vulnerable environment with docker so that we can scan for vulnerabilities
```
# Setup environment command

```

- Get the IP address of the vulnerable environment/machine
```
# Command
docker inspect name-here | grep IPAddrr

```

- Scan
```
# Command

```
