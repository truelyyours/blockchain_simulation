# Projekt Part-2
## running seeds
Put the seed info in config.txt file\
`python3 seed.py -ip 127.0.0.1 -port 8001 `
## running peers
Make sure all seeds in config.txt are running\
`python3 peer.py -ip 127.0.0.1 -port 10001 -hashing_power 1 -global_lambda 10 -block_file blocks.txt`
