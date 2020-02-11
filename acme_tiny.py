#!/usr/bin/env python3
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging, configparser
from urllib.request import urlopen, Request
from urllib.error import HTTPError

DEFAULT_CA = "https://acme-v02.api.letsencrypt.org"
#DEFAULT_CA = "https://acme-staging-v02.api.letsencrypt.org"

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

# helper function base64 encode for jose spec
def _b64(b):
	return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")

# helper function - make request and automatically parse json response
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
		raise IndexError(resp_data) # allow 100 retrys for bad nonces
	if code not in [200, 201, 204]:
		raise ValueError("{0}:\nURL: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code, resp_data))
	return code, resp_data, headers

# helper function make signed requests
def _send_signed_request(account_key, directory, url, payload, err_msg, depth=0):
	payload64 = "" if payload is None else _b64(json.dumps(payload).encode("utf8"))
	protected = copy.deepcopy(account_key["header"])
	protected["url"] = url
	protected["nonce"] = _do_request(directory["newNonce"])[2]["Replay-Nonce"]
	protected64 = _b64(json.dumps(protected).encode("utf8"))
	proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", account_key["filename"]],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode("utf8"))
	if proc.returncode != 0:
		raise IOError("OpenSSL Error: {0}".format(err))
	data = json.dumps({
		"protected": protected64,
		"payload": payload64, "signature": _b64(out),
	})
	try:
		return _do_request(url, data.encode("utf8"), err_msg=err_msg, depth=depth)
	except IndexError: # retry bad nonces (they raise IndexError)
		return _send_signed_request(account_key, directory, url, payload, err_msg, depth=(depth + 1))
	except HTTPError as e:
		return e.code, e.read(), e.headers

def get_account_key(account_key, log):
	with open(account_key, "rb") as f:
		pass

	log.info("Reading account key...")
	proc = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate()
	if proc.returncode != 0:
		raise IOError("OpenSSL Error: {0}".format(err))
	pub_hex, pub_exp = re.search(
		r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
		out.decode("utf8"), re.MULTILINE|re.DOTALL).groups()
	pub_exp = "{0:x}".format(int(pub_exp))
	pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
	header = {
		"alg": "RS256",
		"jwk": {
			"e": _b64(binascii.unhexlify(pub_exp)),
			"kty": "RSA",
			"n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex))),
		},
	}
	accountkey_json = json.dumps(header["jwk"], sort_keys=True, separators=(",", ":"))
	thumbprint = _b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())
	return {"header": header, "thumbprint": thumbprint, "filename": account_key}

def register(account_key, email, log, directory):
	if type(account_key) != dict:
		account_key = get_account_key(account_key, log)

	log.info("Registering account...")
	reg = { "termsOfServiceAgreed": True }
	if email:
		reg["contact"] = ["mailto:" + x for x in [email]]
	code, result, headers = _send_signed_request(account_key, directory, directory["newAccount"], reg, "Error registering")

	account_key["header"]["kid"] = headers["Location"]
	del account_key["header"]["jwk"]

	if code == 201:
		log.info("Registered account " + str(result["createdAt"]))
	elif email:
		log.info("Already registered " + str(result["createdAt"]))
		reg = { "contact": ["mailto:" + x for x in [email]] }
		code, result, headers = _send_signed_request(account_key, directory, headers["Location"], reg, "Error updating contact details")
		if code == 200:
			log.info("Updated account " + str(result["createdAt"]))
		else:
			raise ValueError("Error updating registration: {0} {1}".format(code, result))

def req(config_file, private_key_file, selfsign, log=LOGGER):
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
		cmd.extend(["-x509", "-days", str(365.25 * 200)])

	proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	csr_pem, err = proc.communicate(input=openssl_config.encode("utf8"))
	if err:
		raise ValueError("Error creating {1}:\n{0}".format(err.decode("utf8"),
			"self signed certificate" if selfsign else "certificate request"))

	return csr_pem.decode("utf8")

class ChallengeHandler:
	def __init__(self, hostname, data, account_key, directory, log):
		self.account_key = account_key
		self.directory = directory
		self.log = log
		self.hostname = hostname
		self.type = data["type"]
		self.url = data["url"]
		self.token = re.sub(r"[^A-Za-z0-9_\-]", "_", data["token"])
		self.keyauthorization = "{0}.{1}".format(self.token, account_key["thumbprint"])

	def valid(self):
		# notify challenge are met
		_, result, _ = _send_signed_request(self.account_key, self.directory, self.url, {
			"keyAuthorization": self.keyauthorization,
		}, "Error triggering challenge")
		# wait for challenge to be verified
		attempts = 10
		while attempts > 0:
			attempts = attempts - 1
			_, challenge_status, _ = _send_signed_request(self.account_key, self.directory,
				self.url, None, "Error checking challenge")

			if challenge_status["status"] == "pending":
				time.sleep(2)
			elif challenge_status["status"] == "valid":
				self.log.info("{0} verified".format(self.hostname))
				return True
			else:
				raise ValueError("{0} challenge did not pass: {1}".format(
					self.hostname, challenge_status))
		return False

class Http01ChallengeHandler(ChallengeHandler):
	def __init__(self, hostname, data, account_key, directory, config, log):
		super().__init__(hostname, data, account_key, directory, log)
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

	def valid(self):
		if not self.wellknown_path:
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

		return super().valid()

class Dns01ChallengeHandler(ChallengeHandler):
	def __init__(self, hostname, data, account_key, directory, config, log):
		super().__init__(hostname, data, account_key, directory, log)
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
				self.log.info("Reload: " + output)

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

	def valid(self):
		if not self.zone_file or not self.zone_cmd:
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
							if rdata.rdtype == dns.rdatatype.TXT and rdata.strings[0] == self.txt_value:
								ok = True
					if ok:
						self.log.info(log_message + "OK")
						success = True
					else:
						self.log.info(log_message + "No data")
						failed = True
				except OSError:
					# Ignore unreachable errors
					self.log.info(log_message + "Error")
					pass
				except dns.exception.Timeout:
					# Ignore timeouts
					self.log.info(log_message + "Timeout")
					pass

			if success and not failed:
				return super().valid()
			self.log.info("Retrying")

		return False

CHALLENGE_TYPES = {
	"http-01": Http01ChallengeHandler,
	"dns-01": Dns01ChallengeHandler,
}

def cert(account_key, config_file, request_file, log, directory):
	account_key = get_account_key(account_key, log)

	with open(config_file, "rb") as f:
		pass

	with open(request_file, "rb") as f:
		pass

	config = configparser.ConfigParser()
	config.read(config_file)

	hostnames = config.sections()
	valid = 0
	if not hostnames:
		raise ValueError("No hostnames defined")

	register(account_key, None, log, directory)

	# create a new order
	code, order, order_headers = _send_signed_request(account_key, directory, directory['newOrder'], {
		"identifiers": [{"type": "dns", "value": hostname} for hostname in hostnames]
	}, "Error creating order")

	# verify each hostname
	for auth_url in order["authorizations"]:
		_, authorisation, _ = _send_signed_request(account_key, directory, auth_url, None, "Error getting challenges")
		hostname = authorisation["identifier"]["value"]
		if hostname not in hostnames:
			raise ValueError("Asked to verify {0} which was not requested".format(hostname))

		log.info("Verifying {0}...".format(hostname))

		ok = False
		for challenge in authorisation["challenges"]:
			if challenge["type"] in CHALLENGE_TYPES:
				with CHALLENGE_TYPES[challenge["type"]](hostname, challenge, account_key, directory, config[hostname], log) as c:
					if c.valid():
						valid += 1
						ok = True
						break

		if not ok:
			raise ValueError("No valid challenge types for {0}".format(hostname))

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
	_send_signed_request(account_key, directory, order["finalize"], { "csr": _b64(csr_der) }, "Error finalising order")

	# wait for certificate to be issued
	attempts = 10
	ok = False
	while attempts > 0:
		attempts = attempts - 1
		_, order, _ = _send_signed_request(account_key, directory,
			order_headers["Location"], None, "Error checking challenge")

		if order["status"] in ["pending", "processing"]:
			time.sleep(2)
		elif order["status"] == "valid":
			log.info("Certificate ready")
			ok = True
			break
		else:
			raise ValueError("Certificate was not issued: {0}".format(order))

	# return signed certificate
	_, result, _ = _send_signed_request(account_key, directory, order["certificate"], None, "Certificate download failed")
	log.info("Certificate signed")
	return result

def revoke(account_key, cert, reason, log, directory):
	account_key = get_account_key(account_key, log)

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

	register(account_key, None, log, directory)

	log.info("Revoking certificate...")
	_send_signed_request(account_key, directory, directory["revokeCert"], {
		"certificate": _b64(data),
		"reason": reason,
	}, "Error revoking certificate")
	log.info("Revoked certificate")

def main(argv):
	parser = argparse.ArgumentParser()
	parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
	parser.add_argument("--ca", default=DEFAULT_CA, help="certificate authority, default is Let's Encrypt")
	subparsers = parser.add_subparsers(dest="subparser_name")

	parser_reg = subparsers.add_parser("register")
	parser_reg.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
	parser_reg.add_argument("--email", required=True, help="register account with contact email address")

	parser_req = subparsers.add_parser("req")
	parser_req.add_argument("--config", required=True, help="path to your certificate configuration file")
	parser_req.add_argument("--private-key", required=True, help="path to your private key")

	parser_selfsign = subparsers.add_parser("selfsign")
	parser_selfsign.add_argument("--config", required=True, help="path to your certificate configuration file")
	parser_selfsign.add_argument("--private-key", required=True, help="path to your private key")

	parser_cert = subparsers.add_parser("cert")
	parser_cert.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
	parser_cert.add_argument("--config", required=True, help="path to your certificate configuration file")
	parser_cert.add_argument("--req", required=True, help="path to your certificate request")

	parser_revoke = subparsers.add_parser("revoke")
	parser_revoke.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
	parser_revoke.add_argument("--cert", required=True, help="path to your certificate")
	parser_revoke.add_argument("--reason", required=True, type=int, help="reason code")

	args = parser.parse_args(argv)
	LOGGER.setLevel(args.quiet or LOGGER.level)

	_, directory, _ = _do_request(args.ca + "/directory", err_msg="Error getting directory")

	if args.subparser_name == "register":
		register(args.account_key, args.email, log=LOGGER, directory=directory)
	elif args.subparser_name == "req":
		signed_req = req(args.config, args.private_key, False, log=LOGGER)
		sys.stdout.write(signed_req)
	elif args.subparser_name == "selfsign":
		selfsigned_crt = req(args.config, args.private_key, True, log=LOGGER)
		sys.stdout.write(selfsigned_crt)
	elif args.subparser_name == "cert":
		signed_crt = cert(args.account_key, args.config, args.req, log=LOGGER, directory=directory)
		sys.stdout.write(signed_crt)
	elif args.subparser_name == "revoke":
		revoke(args.account_key, args.cert, args.reason, log=LOGGER, directory=directory)

if __name__ == "__main__":
	main(sys.argv[1:])
