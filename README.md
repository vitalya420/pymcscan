# pymcscan - a silly port checker in python

Run as sudo
```sudo python3 main.py --src-ip=192.168.0.109 --country UA --dst-port=25565 --processes=12 --file=ua_25565.txt```

Tested on DigitalOcean server

`CPU: DO-Regular @ 4x 2.295GHz`
  
`Speed: ~4000 hosts/second on 1 core (~16000 hosts/seconds on 4 cores) `

Tested on personal computer

`CPU: AMD Ryzen 5 4600H with Radeon Graphics @ 12x 3GHz`

`Speed: ~7300 hosts/second on 1 cores (~87600 hosts/second on 12 cores)`

Note: Home router just dies
