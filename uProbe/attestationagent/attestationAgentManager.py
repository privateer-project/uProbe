import util.config
from util.cryptoutils import get_logger, get_current_time, get_ereport_data, get_mrsigner_key, compute_digest_for_values, compute_mac_bytestream, derive_mac_key
import requests
import json
import logging

class AttestationAgentManager:
  def __init__(self, containerId):    
    self.logger = get_logger()
    self.containerId = containerId


  def get_secure_launch_evidence(self):
    self.logger.info(f'Collecting secure launch evidence for uProbe {self.containerId}')
    timestamp = get_current_time()

    user_data = compute_digest_for_values([self.containerId.encode('utf-8'), timestamp.encode('utf-8')])

    mrSignerKey = get_mrsigner_key()

    reportByteStream = get_ereport_data(bytes.fromhex(user_data))
    reportBody = reportByteStream[:-48]

    salt = compute_digest_for_values([timestamp.encode('utf-8')])
    seed = compute_digest_for_values([self.containerId.encode('utf-8'), bytes.fromhex(mrSignerKey)])

    key = derive_mac_key(seedInBytes = bytes.fromhex(seed), saltInBytes = bytes.fromhex(salt))

    reportMac = compute_mac_bytestream(macPayload=reportBody, macKeyInHex=key)

    uProbeEvidence = {
      'containerId': self.containerId,
      'evidenceType': 'SECURE_LAUNCH',
      'timestamp': timestamp,
      'enclaveReport': reportByteStream.hex(), 
      'mac': reportMac.hex()
    }

    self.logger.info(json.dumps(uProbeEvidence))

    securityProbe = util.config.context['SECURITY_PROBE_HOST']
    r = requests.post(f'http://{securityProbe}/api/attestationAgent/uProbeEvidence', data=json.dumps(uProbeEvidence))

    if r.status_code != requests.codes.ok:
      statusCode = r.status_code
      self.logger.error(f'Failed to receive uProbe secure launch digest in uProbe enclave. HTTP Error status {statusCode}')
      raise ValueError(f'Failed to receive uProbe secure launch digest in uProbe enclave. HTTP Error status {statusCode}')

    self.logger.info('Successfully posted uProbe evidence to the infrastructure Security Probe')




    
    


    
