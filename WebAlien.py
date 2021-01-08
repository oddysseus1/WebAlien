#!/usr/bin/env python3

import os
import sys
import re
import io
import subprocess
from subprocess import PIPE, run
import asyncio
from asyncio import iscoroutinefunction
from dataclasses import dataclass, field
from typing import List, Optional
import shutil


def printLogo():
	print()
	print(" __       __            __               ______   __  __                     ")
	print("/  |  _  /  |          /  |             /      \ /  |/  |                    ")
	print("$$ | / \ $$ |  ______  $$ |____        /$$$$$$  |$$ |$$/   ______   _______  ")
	print("$$ |/$  \$$ | /      \ $$      \       $$ |__$$ |$$ |/  | /      \ /       \ ")
	print("$$ /$$$  $$ |/$$$$$$  |$$$$$$$  |      $$    $$ |$$ |$$ |/$$$$$$  |$$$$$$$  |")
	print("$$ $$/$$ $$ |$$    $$ |$$ |  $$ |      $$$$$$$$ |$$ |$$ |$$    $$ |$$ |  $$ |")
	print("$$$$/  $$$$ |$$$$$$$$/ $$ |__$$ |      $$ |  $$ |$$ |$$ |$$$$$$$$/ $$ |  $$ |")
	print("$$$/    $$$ |$$       |$$    $$/       $$ |  $$ |$$ |$$ |$$       |$$ |  $$ |")
	print("$$/      $$/  $$$$$$$/ $$$$$$$/        $$/   $$/ $$/ $$/  $$$$$$$/ $$/   $$/ ")
	print("Version 0.1       Probing the Internet since 2021.                @Oddysseus")
	print()

def mainMenu():
	print("\n########################################################")
	print("#  Options:                                            #")
	print("#  1: Nmap scan                                        #")
	print("#  2: Dirsearch Scan                                   #")
	print("#  3: Nikto Scan                                       #")
	print("#  4: Run All                                          #")
	print("#                                                      #")
	print("########################################################")
	print("\nPlease make a selection (1-4)")
	while True:
		try:
			selection = int(input("> "))
			if selection == 1:
				nmapScan()
				break
			elif selection == 2:
				dirsearchScan()
				break
			elif selection == 3:
				niktoScan()
				break
			elif selection == 4:
				allScan()
				break
			else:
				raise ValueError
		except ValueError:
			print("Invalid selection")
			continue
		break
		
		
def nmapScan():
	print("\n\n########################################################")
	print("Enter an IP address or IP cidr range ex: 127.0.0.1/24:")
	while True:
		try:
			selection = str(input("> "))
			command = ['nmap', '-PN', '-n', '-sV', '--max-retries', '1', '--min-rate', '5000', '-p1-65535', '-oN', 'output/nmapOut.txt', selection]
			if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", selection):
				result = run(command, stdout=PIPE, universal_newlines=True)
				print(result.stdout)
				break
			elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$", selection):
				result = run(command, stdout=PIPE, universal_newlines=True)
				print(result.stdout)
				break			
			else:
				raise ValueError
		except ValueError:
			print("Invalid IP Format")
			continue
		break

def dirsearchScan():
	print("\n\n########################################################")
	print("Enter an IP address or domain:")
	while True:
		try:
			selection = str(input("> "))
			if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", selection):
				subprocess.call("python3 dirsearch/dirsearch.py -u " + selection + " -e php,aspx,jsp,html,js --plain-text-report=output/dirsearchout.txt > /dev/null", shell=True)
				break
			elif re.match(r"\w*\.\w{1,11}$", selection):
				subprocess.call("python3 dirsearch/dirsearch.py -u " + selection + " -e php,aspx,jsp,html,js --plain-text-report=output/dirsearchout.txt > /dev/null", shell=True)
				break
			else:
				raise ValueError
		except ValueError:
			print("Invalid Format")
			continue
		break
	
def dirsearchScanAll(str):
		print(f'Found web ports on {str}')
		print(f'Running dirsearch on {str}')
		subprocess.call("python3 dirsearch/dirsearch.py -u " + str + " -e php,aspx,jsp,html,js --plain-text-report=output/dirsearchout.txt > /dev/null", shell=True)
		with open("output/dirsearchout.txt", "rb") as f:
			filecontent = f.read()
			return filecontent.decode('utf-8')
			
def niktoScan():
	print("\n\n########################################################")
	print("Enter an URL:")
	while True:
		try:
			selection = str(input("> "))
			if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", selection):
				subprocess.call("nikto -host " + selection + " -o output/niktoout.txt -Format txt > /dev/null", shell=True)
				break
			elif re.match(r"\w*\.\w{1,11}$", selection):
				subprocess.call("nikto -host " + selection + " -o output/niktoout.txt -Format txt > /dev/null", shell=True)
				break
			elif re.match(r"^https?:\/\/.*$", selection):
				subprocess.call("nikto -host " + selection + " -o output/niktoout.txt -Format txt > /dev/null", shell=True)
				break
			else:
				raise ValueError
		except ValueError:
			print("Invalid Format")
			continue
		break
	
def niktoScanAll(str):
	print(f'Running nikto on {str}')
	nikto = subprocess.run("nikto -host " + str, shell=True, capture_output=True)
	return nikto.stdout.decode('utf-8')

def allScan():
	print("\n\n########################################################")
	print("Enter an IP address or IP cidr range ex: 127.0.0.1/24:")
	while True:
		try:
			selection = str(input("> "))
			command = ['nmap', '-PN', '-n', '-sV', '--max-retries', '1', '--min-rate', '5000', '-p1-65535', '-oN', 'output/nmapOut.txt', selection]
			if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", selection):
				result = run(command, stdout=PIPE, universal_newlines=True)
				print(result)
				if '80/tcp' in result.stdout:
					dirsearchScan(selection)
					niktoScan(selection)
					break
				elif '443/tcp' in result.stdout:
					dirsearchScan(selection)
					niktoScan(selection)
					break
				break
			elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}", selection):
				asyncio.run(allScanAsync(selection))
				break
			else:
				raise ValueError
		except ValueError:
			import traceback
			print(traceback.format_exc())
			matches = re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}", selection)
			print(f"Invalid IP Format {selection=} {matches!r}")
			continue
		break
	
async def allScanAsync(str):
	queue = asyncio.Queue()
	report_queue = asyncio.Queue()
	await asyncio.gather(
		execute(['bash', '-c', 'nmap -F ' + str], parse_nmap, queue),
		consume(queue, report_queue),
		report(report_queue),
	)
	
@dataclass(frozen=True)
class Port:
	number: str
	protocol: str
	status: str
	service: str
	version: Optional[str] = None
	
@dataclass(frozen=True)
class NMap:
	ip: str
	ports: List[Port] = field(default_factory=list)
	
	@classmethod
	def from_block(cls, block):
		lines = block.split('\n')
		header, *lines = lines
		
		# the ip address is the last thing in the header, so grab it
		ip_match = re.fullmatch(r'\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?', header.split()[-1])
		if not ip_match:
			raise ValueError(f'NMap ip {ip!r} is invalid')
		ip = ip_match.group(1)
			
		ports = []
		for line in lines:
			if match := re.fullmatch(r'(\d{1,5})/(\w+)\s+(open|closed)\s+([\w-]+)(.*)?', line.strip()):
				ports.append(Port(*[i.strip() for i in match.groups()]))
		return cls(ip, ports)
	
async def parse_nmap(stream):
	block, started = b'', False
	while line := await stream.readline():
		if not started and b'Nmap scan report for' in line:
			started = True
		if started:
			if line == b'\n':
				yield NMap.from_block(block.decode('utf-8'))
				started = False
			block += line

async def _stream_subprocess(cmd, parser, queue):
	process = await asyncio.create_subprocess_exec(
		*cmd,
		stdout=asyncio.subprocess.PIPE,
		# not used right now, but also keeps stderr from printing
		stderr=asyncio.subprocess.PIPE,
	)
	async for block in parser(process.stdout):
		for port in block.ports:
			if 'http' in port.service:
				await queue.put(block)
				
	await queue.put(None)
	
	return await process.wait()

async def consume(queue, report_queue):
	while item := await queue.get():
		packaged_data = {
			'nmap': item,
			'dirsearch': dirsearchScanAll(item.ip),
			'nikto': niktoScanAll(item.ip),
		}
		await report_queue.put(packaged_data)
		
	await report_queue.put(None)
	
async def report(queue):
	while item := await queue.get():
		with open('Report.txt', 'a') as f:
			for scan, output in item.items():
				print(scan, file=f)
				print('-----------------', file=f)
				print(output, file=f)
				print(file=f)
			
async def execute(cmd, parser, queue):
	await _stream_subprocess(cmd, parser, queue)

if __name__ == '__main__':
	printLogo()
	mainMenu()
