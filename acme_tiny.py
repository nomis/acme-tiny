#!/usr/bin/env python3
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging, configparser
from urllib.request import urlopen
from urllib.error import HTTPError

#DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
DEFAULT_CA = "https://acme-v01.api.letsencrypt.org"

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

# helper function base64 encode for jose spec
def _b64(b):
	return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")

# helper function make signed requests
def _send_signed_request(account_key, url, payload):
	payload64 = _b64(json.dumps(payload).encode("utf8"))
	protected = copy.deepcopy(account_key["header"])
	protected["nonce"] = urlopen(account_key["CA"] + "/directory").headers["Replay-Nonce"]
	protected64 = _b64(json.dumps(protected).encode("utf8"))
	proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", account_key["filename"]],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode("utf8"))
	if proc.returncode != 0:
		raise IOError("OpenSSL Error: {0}".format(err))
	data = json.dumps({
		"header": account_key["header"], "protected": protected64,
		"payload": payload64, "signature": _b64(out),
	})
	try:
		resp = urlopen(url, data.encode("utf8"))
		return resp.getcode(), resp.read(), resp.headers
	except HTTPError as e:
		return e.code, e.read(), e.headers

def get_account_key(account_key, log=LOGGER, CA=DEFAULT_CA):
	with open(account_key, "rb") as f:
		pass

	# parse account key to get public key
	log.info("Parsing account key...")
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
	return {"header": header, "thumbprint": thumbprint, "filename": account_key, "CA": CA}

def register(account_key, email, log=LOGGER, CA=DEFAULT_CA):
	account_key = get_account_key(account_key, log, CA)

	log.info("Registering account...")
	reg = {
		"resource": "new-reg",
		"contact": ["mailto:" + x for x in [email]],
		"agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf",
	}
	code, result, headers = _send_signed_request(account_key, CA + "/acme/new-reg", reg)
	if code == 201:
		account = json.loads(result.decode("utf8"))
		log.info("Registered account " + str(account["id"]) + " " + str(account["createdAt"]))
	elif code == 409:
		log.info("Already registered")
		reg["resource"] = "reg"
		code, result, headers = _send_signed_request(account_key, headers["Location"], reg)
		if code == 202:
			account = json.loads(result.decode("utf8"))
			log.info("Updated account " + str(account["id"]) + " " + str(account["createdAt"]))
		else:
			raise ValueError("Error updating registration: {0} {1}".format(code, result))
	else:
		raise ValueError("Error registering: {0} {1}".format(code, result))

def req(config_file, private_key_file, log=LOGGER):
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
	proc = subprocess.Popen(["openssl", "req", "-new", "-batch", "-nodes", "-key", private_key_file,
		"-subj", "/CN=" + hostnames[0], "-sha512", "-reqexts", "SAN", "-outform", "PEM", "-config", "/dev/stdin"],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	csr_pem, err = proc.communicate(input=openssl_config.encode("utf8"))
	if err:
		raise ValueError("Error creating certificate request:\n{0}".format(err.decode("utf8")))

	return csr_pem.decode("utf8")

class ChallengeHandler:
	def __init__(self, hostname, data, account_key, log):
		self.account_key = account_key
		self.log = log
		self.hostname = hostname
		self.type = data["type"]
		self.uri = data["uri"]
		self.token = re.sub(r"[^A-Za-z0-9_\-]", "_", data["token"])
		self.keyauthorization = "{0}.{1}".format(self.token, account_key["thumbprint"])

	def valid(self):
		# notify challenge are met
		code, result, headers = _send_signed_request(self.account_key, self.uri, {
			"resource": "challenge",
			"keyAuthorization": self.keyauthorization,
		})
		if code != 202:
			raise ValueError("Error triggering challenge: {0} {1}".format(code, result))
		# wait for challenge to be verified
		attempts = 10
		while attempts > 0:
			attempts = attempts - 1
			try:
				resp = urlopen(self.uri)
				challenge_status = json.loads(resp.read().decode("utf8"))
			except IOError as e:
				raise ValueError("Error checking challenge: {0} {1}".format(
					e.code, json.loads(e.read().decode("utf8"))))

			if challenge_status["status"] == "pending":
				time.sleep(2)
			elif challenge_status["status"] == "valid":
				self.log.info("{0} verified!".format(self.hostname))
				return True
			else:
				raise ValueError("{0} challenge did not pass: {1}".format(
					self.hostname, challenge_status))
		return False

class Http01ChallengeHandler(ChallengeHandler):
	def __init__(self, hostname, data, account_key, config, log):
		super().__init__(hostname, data, account_key, log)
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
	def __init__(self, hostname, data, account_key, config, log):
		super().__init__(hostname, data, account_key, log)
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
			self.log.info(subprocess.check_output(self.zone_cmd, shell=True).decode("utf8"))

	def _find_ns(self):
		import dns.resolver, dns.name

		name = dns.name.from_text(self.zone_name)
		ns = set()
		while True:
			try:
				for hostname in [str(x) for x in dns.resolver.query(name, "NS")]:
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
		import dns.query, dns.message, dns.exception, dns.flags, dns.rdatatype

		if not self.zone_file or not self.zone_cmd:
			return False

		self.reload()

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
				try:
					self.log.info("Query " + ns + "...")
					m = dns.query.udp(q, ns, timeout=5)
					ok = False
					for rrset in m.answer:
						for rdata in rrset:
							if rdata.rdtype == dns.rdatatype.TXT and rdata.strings[0] == self.txt_value:
								self.log.info("  OK")
								ok = True
					if ok:
						success = True
					else:
						self.log.info("  No matching data")
						failed = True
				except OSError:
					# Ignore unreachable errors
					self.log.info("  Error")
					pass
				except dns.exception.Timeout:
					# Ignore timeouts
					self.log.info("  Timeout")
					pass

			if success and not failed:
				return super().valid()
			self.log.info("Retrying")

		return False

CHALLENGE_TYPES = {
	"http-01": Http01ChallengeHandler,
	"dns-01": Dns01ChallengeHandler,
}

def cert(account_key, config_file, request_file, log=LOGGER, CA=DEFAULT_CA):
	account_key = get_account_key(account_key, log, CA)

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

	# verify each hostname
	for hostname in hostnames:
		log.info("Verifying {0}...".format(hostname))

		# get new challenge
		code, result, headers = _send_signed_request(account_key, CA + "/acme/new-authz", {
			"resource": "new-authz",
			"identifier": {"type": "dns", "value": hostname},
		})
		if code != 201:
			raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

		# make the challenge file
		challenges = json.loads(result.decode("utf8"))["challenges"]
		ok = False
		for challenge in challenges:
			if challenge["type"] in CHALLENGE_TYPES:
				with CHALLENGE_TYPES[challenge["type"]](hostname, challenge, account_key, config[hostname], log) as c:
					if c.valid():
						valid += 1
						ok = True
						break

		if not ok:
			raise ValueError("No valid challenge types for {0}".format(hostname))

	if valid != len(hostnames):
		raise ValueError("Unable to validate all hostnames ({0} < {1})".format(valid, len(hostnames)))

	# get the new certificate
	log.info("Signing certificate...")
	proc = subprocess.Popen(["openssl", "req", "-in", request_file, "-outform", "DER"],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	csr_der, err = proc.communicate()
	if err:
		raise ValueError("Error creating certificate request:\n{0}".format(err.decode("utf8")))

	code, result, headers = _send_signed_request(account_key, CA + "/acme/new-cert", {
		"resource": "new-cert",
		"csr": _b64(csr_der),
	})
	if code != 201:
		raise ValueError("Error signing certificate: {0} {1}".format(code, result))

	# return signed certificate!
	log.info("Certificate signed!")
	prefix = ("\n".join("Link: " + x for x in headers["Link"].split(", ")) + "\n") if "Link" in headers else ""
	return prefix + """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
		"\n".join(textwrap.wrap(base64.b64encode(result).decode("utf8"), 64)))

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

	parser_cert = subparsers.add_parser("cert")
	parser_cert.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
	parser_cert.add_argument("--config", required=True, help="path to your certificate configuration file")
	parser_cert.add_argument("--req", required=True, help="path to your certificate request")

	args = parser.parse_args(argv)
	LOGGER.setLevel(args.quiet or LOGGER.level)
	if args.subparser_name == "register":
		register(args.account_key, args.email, log=LOGGER, CA=args.ca)
	elif args.subparser_name == "req":
		signed_req = req(args.config, args.private_key, log=LOGGER)
		sys.stdout.write(signed_req)
	elif args.subparser_name == "cert":
		signed_crt = cert(args.account_key, args.config, args.req, log=LOGGER, CA=args.ca)
		sys.stdout.write(signed_crt)

if __name__ == "__main__":
	main(sys.argv[1:])
