# pymcscan - a silly port checker in python

Run as sudo
```sudo python3 main.py --iface wlp1s0 --src-mac b4:b5:b6:cf:9f:cd --dst-mac b0:a7:b9:bd:e0:29 --src-ip 192.168.0.109 --country UA --dst-port=25565 --processes 1 --file ua.txt```

Tested on DigitalOcean server

`CPU: DO-Regular @ 4x 2.295GHz`
  
`Speed: ~160000 hosts/second on 1 core`
