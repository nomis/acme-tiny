#!/usr/bin/env python3
# Copyright 2015  Daniel Roesler
# Copyright 2015-2018,2020-2021,2023,2025  Simon Arlott
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import base64
import binascii
import configparser
import copy
import fnmatch
import hashlib
import json
import logging
import logging.handlers
import os
import re
import requests
import subprocess
import sys
import tempfile
import textwrap
import time
import traceback
from urllib.request import urlopen, Request
from urllib.error import HTTPError

DEFAULT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
#DEFAULT_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

PEM_RE = re.compile("-----BEGIN CERTIFICATE-----\r?\n.+?\r?\n-----END CERTIFICATE-----\r?\n?", re.DOTALL)

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

def _b64(b):
	return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")

def _do_request(url, data=None, err_msg="Error", depth=0):
	try:
		resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "nomis/acme-tiny"}))
		resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
	except IOError as e:
		resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
		code, headers = getattr(e, "code", None), {}
	try:
		if resp_data:
			resp_data = json.loads(resp_data) # try to parse json results
	except ValueError:
		pass
	if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
		raise IndexError(resp_data) # allow 100 retries for bad nonces
	if code not in [200, 201, 204]:
		raise ValueError("{0}:\nURL: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code, resp_data))
	return code, resp_data, headers

def _pem(data):
	return [match.group(0) for match in PEM_RE.finditer(data)]

def _issuer_names(data):
	names = []

	for cert in _pem(data):
		proc = subprocess.Popen(["openssl", "x509", "-noout", "-issuer"],
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = proc.communicate(cert.encode("utf8"))
		if proc.returncode != 0:
			raise IOError("OpenSSL Error: {0}".format(err))

		names.append(out.decode("utf8").splitlines()[0].split("=", 1)[1])

	return list(reversed(names))

def _ari_certid(data):
	proc = subprocess.Popen(["openssl", "x509", "-noout", "-text"],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate(data.encode("utf8"))
	if proc.returncode != 0:
		raise IOError("OpenSSL Error: {0}".format(err))

	sn = ""
	aki = ""
	in_sn = False
	in_aki = False
	for line in out.decode("utf8").splitlines():
		line = line.strip()
		if in_sn:
			sn += line
			if not line.endswith(":"):
				in_sn = False
		elif in_aki:
			aki += line
			if not line.endswith(":"):
				in_aki = False
		elif line == "Serial Number:":
			in_sn = True
		elif line == "X509v3 Authority Key Identifier:":
			in_aki = True

	if sn and aki and aki.startswith("keyid:"):
		sn = sn.replace(":", "")
		if int(sn[0], 16) >= 8:
			sn = "00" + sn
		sn = _b64(binascii.unhexlify(sn))
		aki = _b64(binascii.unhexlify(aki.split(":", 1)[1].replace(":", "")))
		return f"{aki}.{sn}"
	else:
		raise ValueError(f"Unknown Serial Number/Authority Key Identifier: {sn=!r} {aki=!r}")

class AccountSession:
	def __init__(self, account_key, directory_url):
		self.account_key = account_key
		self.directory_url = directory_url
		self.kid = None
		self.nonce = None

		with open(self.account_key, "rb") as f:
			pass

		log.info("Reading account key...")
		proc = subprocess.Popen(["openssl", "pkey", "-in", self.account_key, "-noout", "-text"],
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = proc.communicate()
		if proc.returncode != 0:
			raise IOError("OpenSSL Error: {0}".format(err))

		out = out.decode("utf8")
		if out.startswith("RSA Private-Key:") or (out.startswith("Private-Key:") and "modulus:" in out and "publicExponent:" in out):
			pub_hex, pub_exp = re.search(
				r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
				out, re.MULTILINE|re.DOTALL).groups()
			pub_exp = "{0:x}".format(int(pub_exp))
			pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
			self.alg = "RS256"
			self.hash_input = hashlib.sha256
			self.sign_cmd = ["-pkeyopt", "digest:sha256"]
			self.jwk = {
				"kty": "RSA",
				"n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex))),
				"e": _b64(binascii.unhexlify(pub_exp)),
			}
		elif out.startswith("Private-Key:") and ("NIST CURVE:" in out):
			pub_hex, pub_curve = re.search(
				r"pub:\n\s+04:([a-f0-9\:\s]+?)\n(?:ASN1 OID: [a-zA-Z0-9]+\n)?NIST CURVE: ([a-zA-Z0-9-]+)\n$",
				out, re.MULTILINE|re.DOTALL).groups()
			pub_hex = re.sub(r"(\s|:)", "", pub_hex)
			pub_sz = len(pub_hex)//2

			if pub_curve not in ["P-256", "P-384", "P-521"]:
				raise ValueError("Unknown curve: " + pub_curve)

			self.alg = { "P-256": "ES256", "P-384": "ES384", "P-521": "ES512" }[pub_curve]
			self.hash_input = {
				"P-256": hashlib.sha256,
				"P-384": hashlib.sha384,
				"P-512": hashlib.sha512,
			}[pub_curve]
			self.sign_cmd = []
			self.jwk = {
				"kty": "EC",
				"crv": pub_curve,
				"x": _b64(binascii.unhexlify(pub_hex[0:pub_sz])),
				"y": _b64(binascii.unhexlify(pub_hex[pub_sz:])),
			}
		elif out.startswith("ED25519 Private-Key:") or out.startswith("ED448 Private-Key:"):
			pub_hex, = re.search(
				r"pub:\n\s+([a-f0-9\:\s]+?)\n$",
				out, re.MULTILINE|re.DOTALL).groups()
			self.alg = "EdDSA"
			self.sign_cmd = ["-rawin"]
			self.hash_input = None
			self.jwk = {
				"kty": "OKP",
				"crv": out.split(" ")[0].replace("ED", "Ed"),
				"x": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex))),
			}
		else:
			raise ValueError("Unknown account key type: " + out.splitlines()[0])
		accountkey_json = json.dumps(self.jwk, sort_keys=True, separators=(",", ":"))
		self.thumbprint = _b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())

	def header(self):
		if self.kid:
			return { "alg": self.alg, "kid": self.kid }
		else:
			return { "alg": self.alg, "jwk": self.jwk }

	def start(self):
		log.info("Getting directory...")
		_, self.directory, _ = _do_request(self.directory_url, err_msg="Error getting directory")

		log.info("Registering account...")
		reg = { "termsOfServiceAgreed": True }
		code, result, headers = self.request(self.directory["newAccount"], reg, "Error registering")

		self.kid = headers["Location"]
		if code == 201:
			log.info("Registered account " + str(result["createdAt"]) + " " + self.kid)
		elif code == 200:
			log.info("Existing account " + str(result["createdAt"]) + " " + self.kid)

	def get_nonce(self):
		if self.nonce is None:
			nonce = _do_request(self.directory["newNonce"])[2]["Replay-Nonce"]
			log.debug("Obtained new nonce " + nonce)
		else:
			nonce = self.nonce
			self.nonce = None
			log.debug("Using nonce " + nonce)
		return nonce

	def _sign_input(self, data):
		if self.hash_input:
			return self.hash_input(data).digest()
		else:
			return data

	def _sign_output(self, data):
		if self.alg.startswith("ES"):
			sz = {
				"ES256": 32,
				"ES384": 48,
				"ES512": 66,
			}[self.alg]
			proc = subprocess.Popen(["openssl", "asn1parse", "-inform", "DER"],
				stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			out, err = proc.communicate(data)
			if proc.returncode != 0:
				raise IOError("OpenSSL Error: {0}".format(err))
			(r, s) = [line.split(":")[-1].ljust(sz, "0") for line in out.decode("utf8").splitlines()[1:3]]
			return binascii.unhexlify(r) + binascii.unhexlify(s)
		else:
			return data

	def sign(self, payload, url, nonce=True):
		payload64 = "" if payload is None else _b64(json.dumps(payload).encode("utf8"))
		protected = self.header()
		protected["url"] = url
		if nonce:
			protected["nonce"] = self.get_nonce()
		protected64 = _b64(json.dumps(protected).encode("utf8"))
		with tempfile.TemporaryFile() as f:
			f.write(self._sign_input("{0}.{1}".format(protected64, payload64).encode("utf8")))
			f.flush()
			f.seek(0)
			proc = subprocess.Popen(["openssl", "pkeyutl", "-sign"] + self.sign_cmd + ["-inkey", self.account_key, "-in", "/dev/fd/0"],
				stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = proc.communicate()
		if proc.returncode != 0:
			raise IOError("OpenSSL Error: {0}".format(err))
		out = self._sign_output(out)
		return {
			"protected": protected64,
			"payload": payload64,
			"signature": _b64(out),
		}

	def request(self, url, payload, err_msg, depth=0):
		try:
			code, data, headers = _do_request(url, json.dumps(self.sign(payload, url)).encode("utf8"), err_msg=err_msg, depth=depth)
			if "Replay-Nonce" in headers:
				self.nonce = headers["Replay-Nonce"]
				log.debug("Saving nonce " + self.nonce)
			return code, data, headers
		except IndexError: # retry bad nonces (they raise IndexError)
			return self.request(url, payload, err_msg, depth=(depth + 1))
		except HTTPError as e:
			return e.code, e.read(), e.headers

def register(session, email):
	session.start()

	if email:
		reg = { "contact": ["mailto:" + x for x in [email]] }
		code, result, _ = session.request(session.kid, reg, "Error updating contact details")
		if code == 200:
			log.info("Updated account " + str(result["createdAt"]) + " " + session.kid)
		else:
			raise ValueError("Error updating registration: {0} {1}".format(code, result))

def change(session, new_session):
	session.start()

	data = new_session.sign({ "account": session.kid, "oldKey": session.jwk }, session.directory["keyChange"], False)
	code, result, _ = session.request(session.directory["keyChange"], data, "Error changing key")
	if code == 200:
		log.info("Changed key")
	else:
		raise ValueError("Error changing key: {0} {1}".format(code, result))

def deactivate(session):
	session.start()

	reg = { "status": "deactivated" }
	code, result, _ = session.request(session.kid, reg, "Error deactivating account")
	if code == 200:
		log.info("Deactivated account")
	else:
		raise ValueError("Error deactivating account: {0} {1}".format(code, result))

def req(config_file, private_key_file, selfsign):
	with open(config_file, "rb") as f:
		pass
	with open(private_key_file, "rb") as f:
		pass

	config = configparser.ConfigParser()
	config.read(config_file)

	hostnames = config.sections()
	if not hostnames:
		raise ValueError("No hostnames defined")

	openssl_config = "[req]\ndistinguished_name=req_distinguished_name\n[req_distinguished_name]\n[SAN]\nsubjectAltName="
	openssl_config = openssl_config + ",".join(["DNS:" + x for x in hostnames])
	cmd = ["openssl", "req", "-new", "-batch", "-nodes", "-key", private_key_file,
		"-subj", "/CN=" + hostnames[0], "-sha512", "-reqexts", "SAN", "-outform", "PEM", "-config", "/dev/stdin"]

	if selfsign:
		cmd.extend(["-x509", "-days", str(int(365.25 * 200))])

	proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	csr_pem, err = proc.communicate(input=openssl_config.encode("utf8"))
	if err:
		raise ValueError("Error creating {1}:\n{0}".format(err.decode("utf8"),
			"self signed certificate" if selfsign else "certificate request"))

	return csr_pem.decode("utf8")

class ChallengeHandler:
	def __init__(self, hostname, data, session):
		self.session = session
		self.hostname = hostname
		self.type = data["type"]
		self.url = data["url"]
		self.token = re.sub(r"[^A-Za-z0-9_\-]", "_", data["token"])
		self.keyauthorization = "{0}.{1}".format(self.token, self.session.thumbprint)

	def supported(self):
		return False

	def prepare(self):
		return False

	def check(self):
		# notify challenge are met
		_, result, _ = self.session.request(self.url, {
			"keyAuthorization": self.keyauthorization,
		}, "Error triggering challenge")
		log.debug("Challenge: {0}".format(repr(result)))

		# wait for challenge to be verified
		attempts = 30
		while attempts > 0:
			attempts = attempts - 1
			_, challenge_status, _ = self.session.request(self.url, None, "Error checking challenge")

			if challenge_status["status"] in ["pending", "processing"]:
				log.info("Challenge status: {0}".format(repr(challenge_status)))
				time.sleep(4)

				if attempts % 10 == 0:
					_, result, _ = self.session.request(self.url, {
						"keyAuthorization": self.keyauthorization,
					}, "Error triggering challenge")
					log.debug("Challenge: {0}".format(repr(result)))
			elif challenge_status["status"] == "valid":
				log.info("Verified {0}".format(self.hostname))
				return True
			else:
				raise ValueError("Challenge did not pass: {0}".format(challenge_status))
		return False

class Http01ChallengeHandler(ChallengeHandler):
	def __init__(self, hostname, data, session, config):
		super().__init__(hostname, data, session)
		path = config.get("http-01_dir")
		self.wellknown_path = os.path.join(path, self.token) if path else None

	def __enter__(self):
		if self.wellknown_path:
			with open(self.wellknown_path, "w") as wellknown_file:
				wellknown_file.write(self.keyauthorization)

		return self

	def __exit__(self, type, value, traceback):
		if self.wellknown_path:
			os.remove(self.wellknown_path)

	def supported(self):
		return bool(self.wellknown_path)

	def prepare(self):
		if not self.supported():
			return False

		# check that the file is in place
		wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(self.hostname, self.token)
		try:
			resp = urlopen(wellknown_url)
			resp_data = resp.read().decode("utf8").strip()
			assert resp_data == self.keyauthorization
		except (IOError, AssertionError):
			raise ValueError("Wrote file to {0}, but couldn't download {1}".format(
				self.wellknown_path, wellknown_url))

		return True

class Dns01ChallengeHandler(ChallengeHandler):
	def __init__(self, hostname, data, session, config):
		super().__init__(hostname, data, session)
		self.zone_file = config.get("dns-01_file")
		self.zone_name = config.get("dns-01_name")
		self.zone_cmd = config.get("dns-01_cmd")
		if not self.zone_name:
			self.zone_name = "_acme-challenge." + hostname + "."
		self.txt_value = _b64(hashlib.sha256(self.keyauthorization.encode("utf8")).digest())

	def _update_zone_file(self):
		content = ""

		with open(self.zone_file, "r") as f:
			for line in f:
				if not line.startswith(self.zone_name + " "):
					content += line

		log.debug("Zone update in {0!r}: {1!r} = {2!r}".format(self.zone_file, self.zone_name, self.txt_value))
		content += self.zone_name + ' 1 TXT "' + self.txt_value + '"\n'

		with open(self.zone_file, "w") as f:
			f.write(content)

	def __enter__(self):
		if self.zone_file:
			self._update_zone_file()

		return self

	def __exit__(self, type, value, traceback):
		self.txt_value = ""

		if self.zone_file:
			self._update_zone_file()

	def reload(self):
		if self.zone_cmd:
			output = subprocess.check_output(self.zone_cmd, shell=True).decode("utf8")
			if output:
				log.info("Reload: " + output)

	def _find_ns(self):
		import dns.resolver, dns.name

		name = dns.name.from_text(self.zone_name)
		ns = set()
		while True:
			try:
				resp = dns.resolver.query(name, "NS")
				if resp.rrset.name != name:
					name = name.parent()
					continue

				for hostname in [str(x) for x in resp]:
					try:
						for rdata in dns.resolver.query(hostname, "A"):
							ns.add(str(rdata))
					except dns.resolver.NXDOMAIN:
						pass
					except dns.resolver.NoAnswer:
						pass

					try:
						for rdata in dns.resolver.query(hostname, "AAAA"):
							ns.add(str(rdata))
					except dns.resolver.NXDOMAIN:
						pass
					except dns.resolver.NoAnswer:
						pass
				break
			except dns.resolver.NXDOMAIN:
				name = name.parent()
			except dns.resolver.NoAnswer:
				name = name.parent()

		return ns

	def supported(self):
		return bool(self.zone_file) and bool(self.zone_cmd)

	def prepare(self):
		if not self.supported():
			return False

		self.reload()

		import dns.query, dns.message, dns.exception, dns.flags, dns.rdatatype

		# Get nameservers for hostname
		nameservers = self._find_ns()

		attempts = 15
		while attempts > 0:
			attempts = attempts - 1
			time.sleep(2)

			# Check all nameservers
			success = False
			failed = False
			q = dns.message.make_query(self.zone_name, "TXT")
			q.flags &= ~dns.flags.RD
			for ns in nameservers:
				log_message = "Query " + ns + " "
				try:
					m = dns.query.udp(q, ns, timeout=5)
					ok = False
					for rrset in m.answer:
						for rdata in rrset:
							if rdata.rdtype == dns.rdatatype.TXT:
								log.debug(log_message + "TXT " + repr(rdata.strings))
							if rdata.rdtype == dns.rdatatype.TXT and rdata.strings[0] == self.txt_value.encode("us-ascii"):
								ok = True
					if ok:
						log.info(log_message + "OK")
						success = True
					else:
						log.info(log_message + "Missing")
						failed = True
				except OSError:
					# Ignore unreachable errors
					log.info(log_message + "Error")
					pass
				except dns.exception.Timeout:
					# Ignore timeouts
					log.info(log_message + "Timeout")
					pass

			if success and not failed:
				return True
			log.info("Retrying")

		return False

CHALLENGE_TYPES = {
	"http-01": Http01ChallengeHandler,
	"dns-01": Dns01ChallengeHandler,
}

def cert(session, config_file, request_file, preferred_path=None):
	with open(config_file, "rb") as f:
		pass

	with open(request_file, "rb") as f:
		pass

	config = configparser.ConfigParser()
	config.read(config_file)

	session.start()

	hostnames = config.sections()
	valid = 0
	if not hostnames:
		raise ValueError("No hostnames defined")

	# create a new order
	code, order, order_headers = session.request(session.directory["newOrder"], {
		"identifiers": [{"type": "dns", "value": hostname} for hostname in hostnames]
	}, "Error creating order")

	for auth_url in order["authorizations"]:
		log.info("Authorisation {0}".format(auth_url))

	# verify each hostname
	for auth_url in order["authorizations"]:
		_, authorisation, _ = session.request(auth_url, None, "Error getting challenges")
		hostname = authorisation["identifier"]["value"]
		log.info("Need to authorise {1} using {2} for {0}".format(auth_url, hostname, repr([challenge["type"] for challenge in authorisation["challenges"]])))

		wildcard_hostname = "*." + hostname
		if hostname not in hostnames and wildcard_hostname not in hostnames:
			raise ValueError("Asked to verify {0} which was not requested".format(hostname))

		config_hostname = hostname
		if hostname not in hostnames and wildcard_hostname in hostnames:
			config_hostname = wildcard_hostname

		log.info("Verifying {0}...".format(hostname))

		ok = False
		for challenge in authorisation["challenges"]:
			if challenge["type"] in CHALLENGE_TYPES:
				with CHALLENGE_TYPES[challenge["type"]](hostname, challenge, session, config[config_hostname]) as c:
					if not c.supported():
						log.info("Unable to support challenge {0}".format(challenge["type"]))
					elif c.prepare():
						log.info("Prepared for challenge {0}".format(challenge["type"]))
						valid += 1

						if c.check():
							ok = True
							break
						else:
							log.info("Timeout checking challenge {0}".format(challenge["type"]))
					else:
						log.info("Failed to prepare challenge {0}".format(challenge["type"]))

		if not valid:
			raise ValueError("No valid challenge types for {0}".format(hostname))

		if not ok:
			raise ValueError("All challenges failed for {0}".format(hostname))

	if valid != len(order["authorizations"]):
		raise ValueError("Unable to complete all authorisations ({0} < {1})".format(valid, len(order["authorizations"])))

	# get the new certificate
	log.info("Signing certificate...")
	proc = subprocess.Popen(["openssl", "req", "-in", request_file, "-outform", "DER"],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	csr_der, err = proc.communicate()
	if err:
		raise ValueError("Error reading certificate request:\n{0}".format(err.decode("utf8")))

	# finalize the order with the csr
	session.request(order["finalize"], { "csr": _b64(csr_der) }, "Error finalising order")

	# wait for certificate to be issued
	attempts = 30
	ok = False
	while attempts > 0:
		attempts = attempts - 1
		_, order, _ = session.request(order_headers["Location"], None, "Error checking challenge")

		if order["status"] in ["pending", "processing"]:
			log.info("Order {0}".format(order["status"]))
			time.sleep(4)
		elif order["status"] == "valid":
			log.info("Certificate ready")
			ok = True
			break
		else:
			raise ValueError("Certificate was not issued: {0}".format(order))

	# return signed certificate
	_, result, headers = session.request(order["certificate"], None, "Certificate download failed")
	results = [(_issuer_names(result), result)]
	log.info("Certificate signed")

	for name, value in headers.items():
		if name == "Link":
			links = requests.utils.parse_header_links(value)
			for link in links:
				if link["rel"] == "alternate":
					log.debug("Alternate: {0}".format(link["url"]))
					_, data, _ = session.request(link["url"], None, "Alternate download failed")
					results.append((_issuer_names(data), data))

	result = None

	if preferred_path is not None:
		for i, value in enumerate(results):
			if result is None:
				path = "/".join(value[0])
				if fnmatch.fnmatchcase(path, preferred_path) or fnmatch.fnmatchcase(path, preferred_path + "/*"):
					result = value
	if result is None:
		result = results[0]

	for i, value in enumerate(results):
		log.debug("Paths: {2}{0}: {1}".format(i, value[0], "*" if result == value else " "))

	return result[1]

def revoke(session, cert, reason):
	with open(cert, "r") as f:
		data = ""
		in_cert = False

		for line in f:
			if line.startswith("-----"):
				in_cert = not in_cert
				if not in_cert:
					break
			elif in_cert:
				data += line

		data = base64.b64decode(data)

	session.start()

	log.info("Revoking certificate...")
	session.request(session.directory["revokeCert"], {
		"certificate": _b64(data),
		"reason": reason,
	}, "Error revoking certificate")
	log.info("Revoked certificate")

def renewalinfo(session, cert):
	with open(cert, "r") as f:
		ari_certid = _ari_certid(f.read())

	session.start()

	log.info("Getting renewal info...")
	_, result, _ = session.request(session.directory["renewalInfo"] + f"/{ari_certid}", {}, "Error getting renewal info")
	print("OK:", ari_certid, result["suggestedWindow"]["start"], result["suggestedWindow"]["end"])

def main(argv):
	parser = argparse.ArgumentParser()
	parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
	parser.add_argument("--verbose", action="store_const", const=logging.DEBUG, help="increase verbosity of output")
	parser.add_argument("--syslog", help="log to syslog with name")
	parser.add_argument("--directory", default=DEFAULT_DIRECTORY, help="certificate authority directory, default is Let's Encrypt")
	subparsers = parser.add_subparsers(dest="subparser_name")

	parser_reg = subparsers.add_parser("register", help="register or modify account")
	parser_reg.add_argument("--account-key", required=True, help="path to your ACMEv2 account private key")
	parser_reg.add_argument("--email", required=True, help="register account with contact email address")

	parser_reg = subparsers.add_parser("change", help="change account private key")
	parser_reg.add_argument("--account-key", required=True, help="path to your ACMEv2 account private key")
	parser_reg.add_argument("--new-account-key", required=True, help="path to your new ACMEv2 account private key")

	parser_reg = subparsers.add_parser("deactivate", help="deactivate account permanently")
	parser_reg.add_argument("--account-key", required=True, help="path to your ACMEv2 account private key")

	parser_req = subparsers.add_parser("req", help="create certificate signing request")
	parser_req.add_argument("--config", required=True, help="path to your certificate configuration file")
	parser_req.add_argument("--private-key", required=True, help="path to your private key")

	parser_selfsign = subparsers.add_parser("selfsign", help="create self-signed certificate")
	parser_selfsign.add_argument("--config", required=True, help="path to your certificate configuration file")
	parser_selfsign.add_argument("--private-key", required=True, help="path to your private key")

	parser_cert = subparsers.add_parser("cert", help="issue a new certificate")
	parser_cert.add_argument("--account-key", required=True, help="path to your ACMEv2 account private key")
	parser_cert.add_argument("--config", required=True, help="path to your certificate configuration file")
	parser_cert.add_argument("--req", required=True, help="path to your certificate request")
	parser_cert.add_argument("--path", help="preferred issuer path")

	parser_revoke = subparsers.add_parser("revoke", help="revoke certificate")
	parser_revoke.add_argument("--account-key", required=True, help="path to your ACMEv2 account private key")
	parser_revoke.add_argument("--cert", required=True, help="path to your certificate")
	parser_revoke.add_argument("--reason", required=True, type=int, help="reason code (0=unspecified, 1=keyCompromise, 3=affiliationChanged, 4=superseded, 5=cessationOfOperation)")

	parser_revoke = subparsers.add_parser("renewalinfo", help="get renewal info for certificate")
	parser_revoke.add_argument("--account-key", required=True, help="path to your ACMEv2 account private key")
	parser_revoke.add_argument("--cert", required=True, help="path to your certificate")

	args = parser.parse_args(argv)
	log.setLevel(args.verbose or args.quiet or log.level)

	if args.syslog:
		handler = logging.handlers.SysLogHandler("/dev/log")
		handler.setFormatter(logging.Formatter(args.syslog + ": %(levelname)s %(message)s"))
		log.addHandler(handler)

	session = AccountSession(args.account_key, args.directory) if "account_key" in args else None

	if args.subparser_name == "register":
		register(session, args.email)
	elif args.subparser_name == "change":
		change(session, AccountSession(args.new_account_key, args.directory))
	elif args.subparser_name == "deactivate":
		deactivate(session)
	elif args.subparser_name == "req":
		signed_req = req(args.config, args.private_key, False)
		sys.stdout.write(signed_req)
	elif args.subparser_name == "selfsign":
		selfsigned_crt = req(args.config, args.private_key, True)
		sys.stdout.write(selfsigned_crt)
	elif args.subparser_name == "cert":
		signed_crt = cert(session, args.config, args.req, args.path)
		sys.stdout.write(signed_crt)
	elif args.subparser_name == "revoke":
		revoke(session, args.cert, args.reason)
	elif args.subparser_name == "renewalinfo":
		renewalinfo(session, args.cert)
	else:
		parser.error("No command specified")

if __name__ == "__main__":
	try:
		main(sys.argv[1:])
	except SystemExit:
		pass
	except:
		for line in traceback.format_exc().strip().split("\n"):
			log.critical(line)
		raise
	sys.stdout.flush()
	sys.stderr.flush()
