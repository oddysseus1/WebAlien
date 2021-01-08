# WebAlien
A python3 tool that combines a few different testing tools to speed up the recon process.  
The tool currently includes: Nmap, Nikto, and Dirsearch.  
The output is all put in 1 report for ease of use.  

## Requirements
Python3.8  
Nmap  
Nikto  

### Installing
Make sure Nmap and Nikto are installed.  
```
sudo apt-get install nmap
sudo apt-get install nikto
```
Install WebAlien
```
sudo git clone https://github.com/oddysseus1/WebAlien
cd WebAlien
```

Install Dirsearch
```
sudo git clone https://github.com/maurosoria/dirsearch.git
```
Run the Tool
```
python3 WebAlien.py
```

