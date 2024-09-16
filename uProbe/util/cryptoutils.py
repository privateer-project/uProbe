import os
import secrets
import time
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def get_tracer_port():
  return 8081

def get_attestation_agent_port():
  return 8080

def create_key_pair(name):
  # Step 1: Generate ECDSA private key
  private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

  # Step 2: Get the public key from the private key
  public_key = private_key.public_key()

  # Step 3: Serialize the private key to PEM format
  pem_private_key = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
  )

  # Step 4: Serialize the public key to PEM format
  pem_public_key = public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
  )

  # Step 5: Write the private key to a file
  with open(f'{name}_private.pem', 'wb') as private_key_file:
      private_key_file.write(pem_private_key)

  # Step 6: Write the public key to a file
  with open(f'{name}_public.pem', 'wb') as public_key_file:
      public_key_file.write(pem_public_key)

  logger = get_logger()
  logger.info(f'Keys have been written to {name}_private.pem and {name}_public.pem.')

def get_ereport_data(userReportBytestream = b'\0' * 64):
  logger = get_logger()

  pathToReport = '/dev/attestation/report'
  if not file_exists(pathToReport):
    logger.debug(f'Report does not exist ({pathToReport}). Are you running the app inside inside an enclave?')
    return b'\0' * 413

  try:
    report_data_size = 0
    if userReportBytestream is None:
      userReportBytestream = []
    else:
      report_data_size = len(userReportBytestream)  
      with open('/dev/attestation/user_report_data', 'wb') as f:
        f.write(userReportBytestream)

    with open(pathToReport, 'rb') as f:
      report = f.read()
      logger.debug(f'Generated SGX report with size = {len(report)} and the following fields:')
      logger.debug(f'  ATTRIBUTES.FLAGS: {report[48:56].hex()}  [ Debug bit: {report[48] & 2 > 0} ]')
      logger.debug(f'  ATTRIBUTES.XFRM:  {report[56:64].hex()}')
      logger.debug(f'  MRENCLAVE:        {report[64:96].hex()}')
      logger.debug(f'  MRSIGNER:         {report[128:160].hex()}')
      logger.debug(f'  ISVPRODID:        {report[256:258].hex()}')
      logger.debug(f'  ISVSVN:           {report[258:260].hex()}')
      logger.debug(f'  REPORTDATA:       {report[320:320+report_data_size].hex()}')
      logger.debug(f'  KEYID:            {report[320+report_data_size:320+report_data_size+32].hex()}')
      logger.debug(f'  MAC:              {report[320+report_data_size+32:320+report_data_size+32+16].hex()}')

      return report
  except Exception as e:
    logger.error(f'Error: Failed to locate {pathToReport} inside the enclave. Using default report')
    raise b'\0' * 413

def get_mrsigner_key():
  logger = get_logger()
  pathToKey = '/dev/attestation/keys/_sgx_mrsigner'
  defaultKey = 'fea66327e5eef8e1392abefb82ea2bb1'

  if not file_exists(pathToKey):
    logger.debug(f'MR SIGNER KEY does not exist ({pathToKey}). Are you running the app inside inside an enclave?')
    return defaultKey

  try:
    with open(pathToKey, 'rb') as f:
      key = f.read()
      return key.hex()
  except Exception as e:
    logger.error('Failed to load mr signer key', exc_info=True)
    return defaultKey

def get_enclave_measurement():    
  try:
    report = get_ereport_data()
    return report[64:96].hex()
  except Exception as e:
    logger = get_logger()
    logger.warning("Using default measurement.")
    return "e1392abefb82ea2bb9fea66327e5eef8765d25346d7a9d5de4df6005703e5907"

def __load_private_key_from_pem__(filename, password = None):
    with open(filename, 'rb') as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password if password else None,
        backend=default_backend()
    )
    return private_key

def __load_public_key_from_pem__(filename):
  with open(filename, 'rb') as f:
      pem_data = f.read()
  public_key = serialization.load_pem_public_key(
      pem_data,
      backend=default_backend()
  )
  return public_key

def sign_message(messageBytestream, nonce, keyName):
    private_key = __load_private_key_from_pem__(keyName)
    
    nonceBytestream = bytes.fromhex(nonce)
    to_be_signed =  nonceBytestream + messageBytestream

    signature = private_key.sign(
        to_be_signed,
        ec.ECDSA(hashes.SHA256())
    )
    return signature.hex()

def verify_message(messageBytestream, nonceInHex, signatureInHex, keyName):
  pubKey = __load_public_key_from_pem__(keyName)

  nonceBytestream = bytes.fromhex(nonceInHex)

  payloadBytestream =  nonceBytestream + messageBytestream
  signature = bytes.fromhex(signatureInHex)

  pubKey.verify(
      signature,
      payloadBytestream,
      ec.ECDSA(hashes.SHA256())
  )
  
def compute_digest_for_values(valuesInByteArray = []):
  aggregated_hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
  
  for value in valuesInByteArray:
    value_hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    value_hasher.update(value)
    aggregated_hasher.update(value_hasher.finalize())

  return aggregated_hasher.finalize().hex()

def get_current_time():
  return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def generate_nonce(seedInHex = ""):
  try:
    nonceInHex = secrets.token_hex(32)

    payload = seedInHex + nonceInHex

    value_hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    value_hasher.update(bytes.fromhex(payload))

    return value_hasher.finalize().hex()
  except Exception as e:
    logger = get_logger()
    logger.error(f'Failed to generate nonce', exc_info=True)

def read_public_key(name):
  logger = get_logger()
  try:
    # Read the PEM public key from the file (in text mode)
    with open(name, 'r', encoding='utf-8') as file:
      public_key_pem = file.read()
        
      return public_key_pem
  except IOError as e:
    logger.error(f'Failed to read file', exc_info=True)
    return None
  except Exception as e:
    logger.error(f'nexpected error', exc_info=True)
    return None

def derive_mac_key(seedInBytes, saltInBytes):
  kdf = Scrypt(
      salt=saltInBytes,
      length=32,
      n=2**14,
      r=8,
      p=1,
      backend=default_backend()
  )
  return kdf.derive(seedInBytes).hex()

def compute_mac_bytestream(macPayload, macKeyInHex):
  try:
    key = bytes.fromhex(macKeyInHex)

    cmac = CMAC(algorithms.AES(key), backend=default_backend())
    cmac.update(macPayload)
    mac_result = cmac.finalize()
    return mac_result
  except Exception as e:
    logger = get_logger()
    logger.error('Failed to compute CMAC', exc_info=True)
    return b'0' * 16

def verify_enclave_report_and_get_appraisal(uProbeEvidence):
  try:
    mrSignerKey = get_mrsigner_key()

    salt = compute_digest_for_values([uProbeEvidence['timestamp'].encode('utf-8')])
    seed = compute_digest_for_values([uProbeEvidence['containerId'].encode('utf-8'), bytes.fromhex(mrSignerKey)])

    retrievedKey = derive_mac_key(seedInBytes = bytes.fromhex(seed), saltInBytes = bytes.fromhex(salt))
    
    reportByteArray = bytes.fromhex(uProbeEvidence['enclaveReport'])
    reportBody = reportByteArray[:-48]

    computeMac = compute_mac_bytestream(macPayload=reportBody, macKeyInHex=retrievedKey)
    if computeMac.hex() == uProbeEvidence['mac']:
      return 1 
    else:
      return 0
  except Exception as e:
    logger = get_logger()
    logger.error(f'Failed to verify the enclave report', exc_info=True)
    return 0

def file_exists(filePath = ''):
  return os.path.isfile(filePath)

def get_logger(filename=None, prefix=''):
  logger = logging.getLogger('uProbe')

  if logger.hasHandlers():
    return logger

  if filename is None:
    logFilename = 'uprobe.log'
  else:
    logFilename = filename

  logger.setLevel(logging.DEBUG)
  handler = logging.FileHandler(logFilename)
  handler.setLevel(logging.DEBUG)
  formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  handler.setFormatter(formatter)
  logger.addHandler(handler)

  return logger
